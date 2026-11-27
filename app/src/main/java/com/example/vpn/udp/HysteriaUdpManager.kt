package com.example.vpn.udp

import android.content.Context
import com.example.vpn.model.VpnServer
import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.io.InputStreamReader
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

object HysteriaUdpManager {

  const val LOCAL_SOCKS_HOST = "127.0.0.1"
  const val LOCAL_SOCKS_PORT = 10809
  const val DEFAULT_PORT_RANGE = "6000-19999"
  const val FALLBACK_PORT = "5667"

  private const val CONFIG_FILENAME = "hysteria_udp_config.json"
  private const val BYTES_PER_MB = 1048576L
  private const val CONN_WINDOW_MULTIPLIER = 2621440L
  private const val ATTEMPT_TIMEOUT_MS = 7_000L

  private val ipv4Regex = Regex("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$")
  private val processRef = AtomicReference<Process?>(null)
  private val outputTail = StringBuilder()

  val isRunning: Boolean
    get() = processRef.get()?.isAlive == true

  fun isIpv4Literal(host: String): Boolean {
    val match = ipv4Regex.matchEntire(host.trim()) ?: return false
    return (1..4).all { index ->
      val octet = match.groupValues[index].toIntOrNull() ?: return@all false
      octet in 0..255
    }
  }

  fun resolveIpv4Address(host: String): String {
    val cleanHost = host.trim().removePrefix("[").removeSuffix("]")
    if (cleanHost.isEmpty()) return cleanHost
    if (isIpv4Literal(cleanHost)) return cleanHost
    val addresses = InetAddress.getAllByName(cleanHost)
    val ipv4 = addresses.firstOrNull { it is Inet4Address }?.hostAddress
    return ipv4
      ?: InetAddress.getByName(cleanHost).hostAddress
      ?: throw IOException("Unable to resolve IPv4 address for $cleanHost")
  }

  fun buildConfigJson(
    server: VpnServer,
    resolvedIp: String = server.address.trim(),
    portOverride: String? = null,
  ): String {
    val originalHost = server.address.trim()
    val targetIp = resolvedIp.trim().ifBlank { originalHost }
    val formattedIp =
      if (targetIp.contains(":") && !targetIp.startsWith("[")) "[$targetIp]" else targetIp
    val portRange = portOverride?.trim()?.ifBlank { null } ?: server.effectiveUdpPortRange
    val serverEndpoint = "$formattedIp:$portRange"
    val auth = server.password
    val window = server.udpReceiveWindow.coerceAtLeast(1).toLong()
    val recvWindowConn = window * BYTES_PER_MB
    val recvWindow = window * CONN_WINDOW_MULTIPLIER
    val includeServerName =
      originalHost.isNotEmpty() && !isIpv4Literal(originalHost) && !originalHost.contains(":")

    return buildString {
      append("{\n")
      append("  \"server\": \"${escapeJson(serverEndpoint)}\",\n")
      if (includeServerName) {
        append("  \"server_name\": \"${escapeJson(originalHost)}\",\n")
      }
      append("  \"protocol\": \"udp\",\n")
      append("  \"up_mbps\": 100,\n")
      append("  \"down_mbps\": 100,\n")
      append("  \"handshake_timeout\": 5,\n")
      append("  \"obfs\": \"${escapeJson(auth)}\",\n")
      append("  \"auth_str\": \"${escapeJson(auth)}\",\n")
      append("  \"recv_window_conn\": $recvWindowConn,\n")
      append("  \"recv_window\": $recvWindow,\n")
      append("  \"insecure\": true,\n")
      append("  \"socks5\": {\n")
      append("    \"listen\": \"$LOCAL_SOCKS_HOST:$LOCAL_SOCKS_PORT\"\n")
      append("  }\n")
      append("}\n")
    }
  }

  fun buildCommand(binaryPath: String, configPath: String): List<String> {
    return listOf(
      binaryPath,
      "client",
      "--no-check",
      "-c",
      configPath,
    )
  }

  @Synchronized
  fun start(context: Context, server: VpnServer): Result<Unit> {
    stop()
    return runCatching {
        val host = server.address.trim()
        require(host.isNotEmpty()) { "UDP Server Host / IP is required." }
        require(server.password.isNotEmpty()) { "UDP Password / Auth is required." }

        val nativeDir = context.applicationInfo.nativeLibraryDir
        val binaryFile = File(nativeDir, "libhysteria.so")
        if (!binaryFile.exists()) {
          error("Hysteria UDP client binary (libhysteria.so) not found in native library directory.")
        }
        if (!binaryFile.canExecute()) {
          runCatching { binaryFile.setExecutable(true, false) }
        }

        val resolvedIp =
          runCatching { resolveIpv4Address(host) }
            .getOrElse { err ->
              throw IOException("DNS lookup failed for $host: ${err.message}", err)
            }

        val primaryPort = server.effectiveUdpPortRange.ifBlank { DEFAULT_PORT_RANGE }
        val portAttempts =
          if (primaryPort == FALLBACK_PORT) {
            listOf(FALLBACK_PORT)
          } else {
            listOf(primaryPort, FALLBACK_PORT)
          }

        var lastError: Throwable? = null
        for (portTarget in portAttempts) {
          val attemptResult =
            runCatching {
              startAttempt(
                context = context,
                binaryFile = binaryFile,
                server = server,
                resolvedIp = resolvedIp,
                portTarget = portTarget,
              )
            }
          if (attemptResult.isSuccess) {
            return@runCatching
          }
          lastError = attemptResult.exceptionOrNull()
          stop()
        }

        throw (lastError ?: IOException("Failed to establish ZIVPN UDP tunnel."))
      }
      .onFailure {
        stop()
      }
  }

  private fun startAttempt(
    context: Context,
    binaryFile: File,
    server: VpnServer,
    resolvedIp: String,
    portTarget: String,
  ) {
    stop()
    val configFile = File(context.filesDir, CONFIG_FILENAME)
    configFile.writeText(
      buildConfigJson(server = server, resolvedIp = resolvedIp, portOverride = portTarget),
      StandardCharsets.UTF_8,
    )

    val command = buildCommand(binaryFile.absolutePath, configFile.absolutePath)
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
                  if (outputTail.length > 3072) {
                    outputTail.delete(0, outputTail.length - 1536)
                  }
                  outputTail.append(text).append('\n')
                }
              }
            }
          }
        },
        "pao-hysteria-log",
      )
      .apply { isDaemon = true }
      .start()

    waitForLocalSocksReady(process, portTarget)
  }

  private fun waitForLocalSocksReady(process: Process, portTarget: String) {
    val deadlineMs = System.currentTimeMillis() + ATTEMPT_TIMEOUT_MS
    while (System.currentTimeMillis() < deadlineMs) {
      if (!process.isAlive) {
        val exitCode = runCatching { process.exitValue() }.getOrDefault(-1)
        val details = synchronized(outputTail) { outputTail.toString().trim() }
        throw IOException(
          if (details.isNotEmpty()) "ZIVPN UDP ($portTarget) failed ($exitCode): $details"
          else "Hysteria UDP ($portTarget) exited unexpectedly ($exitCode)."
        )
      }
      val ready =
        runCatching {
            Socket().use { socket ->
              socket.connect(InetSocketAddress(LOCAL_SOCKS_HOST, LOCAL_SOCKS_PORT), 200)
            }
            true
          }
          .getOrDefault(false)
      if (ready) return
      Thread.sleep(100L)
    }
    val details = synchronized(outputTail) { outputTail.toString().trim() }
    throw IOException(
      if (details.isNotEmpty()) {
        "Timed out on ZIVPN UDP ($portTarget): $details"
      } else {
        "Timed out waiting for ZIVPN UDP ($portTarget) on $LOCAL_SOCKS_HOST:$LOCAL_SOCKS_PORT."
      }
    )
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

  private fun escapeJson(value: String): String {
    val sb = StringBuilder(value.length + 8)
    for (ch in value) {
      when (ch) {
        '\\' -> sb.append("\\\\")
        '"' -> sb.append("\\\"")
        '\n' -> sb.append("\\n")
        '\r' -> sb.append("\\r")
        '\t' -> sb.append("\\t")
        else -> sb.append(ch)
      }
    }
    return sb.toString()
  }
}
