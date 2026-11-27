package com.example.vpn.ssh

import android.content.Context
import com.example.vpn.model.VpnServer
import com.example.vpn.parser.VpnLinkParser
import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

object SlowDnsManager {

  const val LOCAL_LISTEN_HOST = "127.0.0.1"
  const val LOCAL_LISTEN_PORT = 7000

  private val processRef = AtomicReference<Process?>(null)
  private val outputTail = StringBuilder()

  val isRunning: Boolean
    get() = processRef.get()?.isAlive == true

  fun buildCommand(binaryPath: String, server: VpnServer): List<String> {
    val rawDnsIp = server.slowDnsServerIp.trim().ifBlank { "8.8.8.8" }
    val udpEndpoint = if (rawDnsIp.contains(":")) rawDnsIp else "$rawDnsIp:53"
    val pubkey = server.slowDnsPublicKey.trim()
    val nsDomain = VpnLinkParser.sanitizeSlowDnsNameserver(server.slowDnsNameserver)
    return listOf(
      binaryPath,
      "-udp",
      udpEndpoint,
      "-pubkey",
      pubkey,
      nsDomain,
      "$LOCAL_LISTEN_HOST:$LOCAL_LISTEN_PORT",
    )
  }

  @Synchronized
  fun start(context: Context, server: VpnServer): Result<Unit> {
    stop()
    return runCatching {
      val pubkey = server.slowDnsPublicKey.trim()
      val nsDomain = VpnLinkParser.sanitizeSlowDnsNameserver(server.slowDnsNameserver)
      require(pubkey.length == 64 && pubkey.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
        "SlowDNS Public Key must be a 64-character hex string."
      }
      require(nsDomain.isNotEmpty()) { "SlowDNS Nameserver (NS Domain) is required." }

      val nativeDir = context.applicationInfo.nativeLibraryDir
      val binaryFile = File(nativeDir, "libdnstt.so")
      if (!binaryFile.exists()) {
        error("SlowDNS client binary (libdnstt.so) not found in native library directory.")
      }
      if (!binaryFile.canExecute()) {
        runCatching { binaryFile.setExecutable(true, false) }
      }

      val command = buildCommand(binaryFile.absolutePath, server)
      synchronized(outputTail) { outputTail.clear() }

      val process =
        ProcessBuilder(command)
          .directory(context.filesDir)
          .redirectErrorStream(true)
          .start()
      processRef.set(process)

      Thread(
          {
            runCatching {
              BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                  val text = line.orEmpty()
                  synchronized(outputTail) {
                    if (outputTail.length > 2048) {
                      outputTail.delete(0, outputTail.length - 1024)
                    }
                    outputTail.append(text).append('\n')
                  }
                }
              }
            }
          },
          "pao-dnstt-log",
        )
        .apply { isDaemon = true }
        .start()

      waitForLocalPortReady(process)
    }.onFailure {
      stop()
    }
  }

  private fun waitForLocalPortReady(process: Process) {
    val deadlineMs = System.currentTimeMillis() + 10_000L
    while (System.currentTimeMillis() < deadlineMs) {
      if (!process.isAlive) {
        val exitCode = runCatching { process.exitValue() }.getOrDefault(-1)
        val details = synchronized(outputTail) { outputTail.toString().trim() }
        throw IOException(
          if (details.isNotEmpty()) "SlowDNS failed ($exitCode): $details"
          else "SlowDNS process exited unexpectedly ($exitCode)."
        )
      }
      val ready =
        runCatching {
            Socket().use { socket ->
              socket.connect(InetSocketAddress(LOCAL_LISTEN_HOST, LOCAL_LISTEN_PORT), 200)
            }
            true
          }
          .getOrDefault(false)
      if (ready) return
      Thread.sleep(100L)
    }
    throw IOException("Timed out waiting for SlowDNS local tunnel on $LOCAL_LISTEN_HOST:$LOCAL_LISTEN_PORT.")
  }

  @Synchronized
  fun stop() {
    val proc = processRef.getAndSet(null) ?: return
    runCatching {
      proc.destroy()
      if (!proc.waitFor(300L, TimeUnit.MILLISECONDS)) {
        proc.destroyForcibly()
      }
    }
  }
}
