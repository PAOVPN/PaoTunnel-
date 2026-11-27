package com.example.vpn.ssh

import com.example.vpn.model.VpnServer
import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.jcraft.jsch.UIKeyboardInteractive
import com.jcraft.jsch.UserInfo
import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

object SshTunnelManager {

  const val DEFAULT_LOCAL_SOCKS_PORT = 10808

  private var session: Session? = null
  private var serverSocket: ServerSocket? = null
  private var acceptThread: Thread? = null
  private val running = AtomicBoolean(false)
  private val relayExecutor = Executors.newCachedThreadPool()

  private val totalUplinkBytes = AtomicLong(0L)
  private val totalDownlinkBytes = AtomicLong(0L)
  private var lastReportedUplink = 0L
  private var lastReportedDownlink = 0L

  val isRunning: Boolean
    get() = running.get() && session?.isConnected == true && serverSocket?.isClosed == false

  @Synchronized
  fun start(
    server: VpnServer,
    localSocksPort: Int = DEFAULT_LOCAL_SOCKS_PORT,
  ): Result<Unit> {
    stop()
    return runCatching {
      totalUplinkBytes.set(0L)
      totalDownlinkBytes.set(0L)
      lastReportedUplink = 0L
      lastReportedDownlink = 0L

      val jsch = JSch()
      val isSlowDns = server.isSlowDns
      val targetHost = if (isSlowDns) SlowDnsManager.LOCAL_LISTEN_HOST else server.address.trim()
      val targetPort = if (isSlowDns) SlowDnsManager.LOCAL_LISTEN_PORT else server.port
      val sshSession = jsch.getSession(server.username, targetHost, targetPort)
      sshSession.setPassword(server.password)
      sshSession.setConfig("StrictHostKeyChecking", "no")
      sshSession.setConfig("PreferredAuthentications", "password,keyboard-interactive")
      sshSession.userInfo = PasswordUserInfo(server.password)
      if (!isSlowDns) {
        sshSession.setSocketFactory(
          PayloadSocketFactory(
            rawPayload = server.payload,
            proxyHost = server.sshProxyHost,
            proxyPort = server.sshProxyPort,
          )
        )
      }
      val timeoutMs = if (isSlowDns) 30_000 else 20_000
      sshSession.setTimeout(timeoutMs)
      sshSession.setServerAliveInterval(15_000)
      sshSession.setServerAliveCountMax(3)
      sshSession.connect(timeoutMs)

      val boundSocket =
        ServerSocket(localSocksPort, 128, InetAddress.getByName("127.0.0.1")).apply {
          reuseAddress = true
        }

      session = sshSession
      serverSocket = boundSocket
      running.set(true)

      val acceptor =
        Thread(
            {
              while (running.get() && !boundSocket.isClosed) {
                val client =
                  try {
                    boundSocket.accept()
                  } catch (_: IOException) {
                    break
                  }
                relayExecutor.execute { handleSocks5Client(client, sshSession) }
              }
            },
            "pao-ssh-socks5-accept",
          )
          .apply { isDaemon = true }
      acceptThread = acceptor
      acceptor.start()
    }.onFailure {
      stop()
    }
  }

  @Synchronized
  fun stop() {
    running.set(false)
    runCatching { serverSocket?.close() }
    serverSocket = null
    runCatching { acceptThread?.interrupt() }
    acceptThread = null
    runCatching { session?.disconnect() }
    session = null
  }

  @Synchronized
  fun queryTrafficDelta(): Pair<Long, Long> {
    val currentUp = totalUplinkBytes.get()
    val currentDown = totalDownlinkBytes.get()
    val deltaUp = (currentUp - lastReportedUplink).coerceAtLeast(0L)
    val deltaDown = (currentDown - lastReportedDownlink).coerceAtLeast(0L)
    lastReportedUplink = currentUp
    lastReportedDownlink = currentDown
    return deltaUp to deltaDown
  }

  private fun handleSocks5Client(clientSocket: Socket, sshSession: Session) {
    clientSocket.use { client ->
      var channel: ChannelDirectTCPIP? = null
      try {
        client.tcpNoDelay = true
        client.soTimeout = 30_000
        val input = DataInputStream(client.getInputStream())
        val output = client.getOutputStream()

        // 1. SOCKS5 Auth Greeting (RFC 1928)
        val ver = input.readUnsignedByte()
        if (ver != 0x05) return
        val nMethods = input.readUnsignedByte()
        val methods = ByteArray(nMethods)
        input.readFully(methods)
        // Accept NO AUTHENTICATION REQUIRED (0x00)
        output.write(byteArrayOf(0x05, 0x00))
        output.flush()

        // 2. SOCKS5 Connection Request
        val reqVer = input.readUnsignedByte()
        val cmd = input.readUnsignedByte()
        input.readUnsignedByte() // RSV
        val atyp = input.readUnsignedByte()
        if (reqVer != 0x05) return

        val destHost =
          when (atyp) {
            0x01 -> {
              val ipv4 = ByteArray(4)
              input.readFully(ipv4)
              InetAddress.getByAddress(ipv4).hostAddress ?: return
            }
            0x03 -> {
              val len = input.readUnsignedByte()
              val domainBytes = ByteArray(len)
              input.readFully(domainBytes)
              String(domainBytes, StandardCharsets.UTF_8)
            }
            0x04 -> {
              val ipv6 = ByteArray(16)
              input.readFully(ipv6)
              InetAddress.getByAddress(ipv6).hostAddress ?: return
            }
            else -> {
              sendSocksReply(output, 0x08) // Address type not supported
              return
            }
          }
        val destPort = input.readUnsignedShort()

        if (cmd != 0x01) {
          sendSocksReply(output, 0x07) // Command not supported (only TCP CONNECT)
          return
        }
        if (!sshSession.isConnected) {
          sendSocksReply(output, 0x01)
          return
        }

        val tcpChannel = sshSession.openChannel("direct-tcpip") as ChannelDirectTCPIP
        channel = tcpChannel
        tcpChannel.setHost(destHost)
        tcpChannel.setPort(destPort)
        val channelOut = tcpChannel.outputStream
        val channelIn = tcpChannel.inputStream
        tcpChannel.connect(15_000)

        client.soTimeout = 0
        sendSocksReply(output, 0x00)

        // Bidirectional pipe between Xray tun2socks client and SSH direct-tcpip channel
        val upFuture =
          relayExecutor.submit {
            pumpStream(
              source = input,
              sink = channelOut,
              counter = totalUplinkBytes,
              closeSinkOnEnd = true,
            )
          }
        pumpStream(
          source = channelIn,
          sink = output,
          counter = totalDownlinkBytes,
          closeSinkOnEnd = false,
        )
        runCatching { upFuture.get() }
      } catch (_: EOFException) {
        // Client closed gracefully
      } catch (_: Exception) {
        // Connection refused or SSH channel closed
      } finally {
        runCatching { channel?.disconnect() }
      }
    }
  }

  private fun sendSocksReply(output: OutputStream, status: Int) {
    runCatching {
      output.write(
        byteArrayOf(0x05, status.toByte(), 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
      )
      output.flush()
    }
  }

  private fun pumpStream(
    source: InputStream,
    sink: OutputStream,
    counter: AtomicLong,
    closeSinkOnEnd: Boolean,
  ) {
    val buffer = ByteArray(16 * 1024)
    try {
      while (running.get()) {
        val read = source.read(buffer)
        if (read == -1) break
        sink.write(buffer, 0, read)
        sink.flush()
        counter.addAndGet(read.toLong())
      }
    } catch (_: IOException) {
      // Stream closed
    } finally {
      if (closeSinkOnEnd) {
        runCatching { sink.close() }
      }
    }
  }

  private class PasswordUserInfo(private val pass: String) : UserInfo, UIKeyboardInteractive {
    override fun getPassphrase(): String = ""

    override fun getPassword(): String = pass

    override fun promptPassword(message: String?): Boolean = true

    override fun promptPassphrase(message: String?): Boolean = false

    override fun promptYesNo(message: String?): Boolean = true

    override fun showMessage(message: String?) = Unit

    override fun promptKeyboardInteractive(
      destination: String?,
      name: String?,
      instruction: String?,
      prompt: Array<out String>?,
      echo: BooleanArray?,
    ): Array<String> {
      return Array(prompt?.size ?: 1) { pass }
    }
  }
}
