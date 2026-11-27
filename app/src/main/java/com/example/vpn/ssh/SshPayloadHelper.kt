package com.example.vpn.ssh

import com.jcraft.jsch.SocketFactory
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets

internal object SshPayloadHelper {

  data class PayloadSegment(
    val bytes: ByteArray,
    val delayAfterMs: Long = 0L,
  )

  private val splitRegex = Regex("\\[(split|delay_split|instant_split)]", RegexOption.IGNORE_CASE)

  fun formatPayload(rawTemplate: String, host: String, port: Int): String {
    if (rawTemplate.isBlank()) return ""
    var formatted =
      rawTemplate
        .replace("\\r\\n", "\r\n")
        .replace("\\n\\r", "\n\r")
        .replace("\\r", "\r")
        .replace("\\n", "\n")

    formatted =
      formatted
        .replace("[host_port]", "$host:$port", ignoreCase = true)
        .replace("[host]", host, ignoreCase = true)
        .replace("[port]", port.toString(), ignoreCase = true)
        .replace("[protocol]", "HTTP/1.1", ignoreCase = true)
        .replace(
          "[raw]",
          "CONNECT $host:$port HTTP/1.1\r\nHost: $host:$port\r\n\r\n",
          ignoreCase = true,
        )
        .replace(
          "[real_raw]",
          "CONNECT $host:$port HTTP/1.1\r\nHost: $host:$port\r\n\r\n",
          ignoreCase = true,
        )
        .replace(
          "[ua]",
          "Mozilla/5.0 (Linux; Android 14; Mobile) AppleWebKit/537.36",
          ignoreCase = true,
        )
        .replace("[crlf]", "\r\n", ignoreCase = true)
        .replace("[lfcr]", "\n\r", ignoreCase = true)
        .replace("[cr]", "\r", ignoreCase = true)
        .replace("[lf]", "\n", ignoreCase = true)

    // Normalize bare LF into CRLF for HTTP compatibility if user typed multiline headers
    if (!formatted.contains("\r") && formatted.contains("\n")) {
      formatted = formatted.replace("\n", "\r\n")
    }
    if (!formatted.endsWith("\r\n\r\n") &&
      (formatted.startsWith("GET ", ignoreCase = true) ||
        formatted.startsWith("POST ", ignoreCase = true) ||
        formatted.startsWith("HEAD ", ignoreCase = true) ||
        formatted.startsWith("PUT ", ignoreCase = true) ||
        formatted.startsWith("CONNECT ", ignoreCase = true))
    ) {
      formatted = formatted.trimEnd('\r', '\n') + "\r\n\r\n"
    }
    return formatted
  }

  fun splitSegments(formattedPayload: String): List<PayloadSegment> {
    if (formattedPayload.isEmpty()) return emptyList()
    val matches = splitRegex.findAll(formattedPayload).toList()
    if (matches.isEmpty()) {
      return listOf(PayloadSegment(formattedPayload.toByteArray(StandardCharsets.UTF_8)))
    }
    val segments = mutableListOf<PayloadSegment>()
    var cursor = 0
    for (match in matches) {
      val chunk = formattedPayload.substring(cursor, match.range.first)
      val tag = match.groupValues[1].lowercase()
      val delayMs = if (tag == "delay_split") 80L else 0L
      if (chunk.isNotEmpty()) {
        segments.add(PayloadSegment(chunk.toByteArray(StandardCharsets.UTF_8), delayMs))
      }
      cursor = match.range.last + 1
    }
    if (cursor < formattedPayload.length) {
      val tail = formattedPayload.substring(cursor)
      if (tail.isNotEmpty()) {
        segments.add(PayloadSegment(tail.toByteArray(StandardCharsets.UTF_8), 0L))
      }
    }
    return segments
  }
}

internal class PayloadSocketFactory(
  private val rawPayload: String,
  private val connectTimeoutMs: Int = 15_000,
) : SocketFactory {

  override fun createSocket(host: String, port: Int): Socket {
    val socket = Socket()
    socket.tcpNoDelay = true
    socket.soTimeout = connectTimeoutMs
    socket.connect(InetSocketAddress(host, port), connectTimeoutMs)

    if (rawPayload.isBlank()) {
      socket.soTimeout = 0
      return socket
    }

    val formatted = SshPayloadHelper.formatPayload(rawPayload, host, port)
    val segments = SshPayloadHelper.splitSegments(formatted)
    val out = socket.getOutputStream()
    for (segment in segments) {
      out.write(segment.bytes)
      out.flush()
      if (segment.delayAfterMs > 0L) {
        Thread.sleep(segment.delayAfterMs)
      }
    }

    val pushbackIn = PushbackInputStream(socket.getInputStream(), 8192)
    consumeOptionalHttpUpgradeResponse(pushbackIn)
    socket.soTimeout = 0

    return object : Socket() {
      override fun getInputStream(): InputStream = pushbackIn

      override fun getOutputStream(): OutputStream = socket.getOutputStream()

      override fun close() = socket.close()

      override fun isClosed(): Boolean = socket.isClosed

      override fun isConnected(): Boolean = socket.isConnected

      override fun setSoTimeout(timeout: Int) {
        socket.soTimeout = timeout
      }

      override fun getSoTimeout(): Int = socket.soTimeout

      override fun setTcpNoDelay(on: Boolean) {
        socket.tcpNoDelay = on
      }

      override fun getTcpNoDelay(): Boolean = socket.tcpNoDelay

      override fun shutdownInput() = socket.shutdownInput()

      override fun shutdownOutput() = socket.shutdownOutput()
    }
  }

  override fun getInputStream(socket: Socket): InputStream = socket.getInputStream()

  override fun getOutputStream(socket: Socket): OutputStream = socket.getOutputStream()

  private fun consumeOptionalHttpUpgradeResponse(input: PushbackInputStream) {
    val peekBuf = ByteArray(4)
    var readCount = 0
    while (readCount < peekBuf.size) {
      val b = input.read()
      if (b == -1) break
      peekBuf[readCount++] = b.toByte()
    }
    if (readCount == 0) {
      throw IOException("Server closed connection after sending payload.")
    }

    val prefix = String(peekBuf, 0, readCount, StandardCharsets.US_ASCII)
    if (!prefix.startsWith("HTTP", ignoreCase = true)) {
      // Server immediately sent SSH banner (e.g. "SSH-2.0-..."); unread peeked bytes for JSch.
      input.unread(peekBuf, 0, readCount)
      return
    }

    // Consume HTTP response headers until \r\n\r\n (or \n\n)
    val headerBuffer = ByteArrayOutputStream()
    headerBuffer.write(peekBuf, 0, readCount)

    var totalBytes = readCount
    while (totalBytes < 16_384) {
      val next = input.read()
      if (next == -1) break
      headerBuffer.write(next)
      totalBytes++
      if (next == '\n'.code && endsWithHeaderTerminator(headerBuffer.toByteArray())) {
        break
      }
    }

    val headerText = headerBuffer.toString(StandardCharsets.US_ASCII.name())
    val statusLine = headerText.lineSequence().firstOrNull().orEmpty().trim()
    val statusCode = statusLine.split(Regex("\\s+")).getOrNull(1)?.toIntOrNull()
    if (statusCode != null && statusCode !in 100..299) {
      throw IOException("SSH payload handshake failed: $statusLine")
    }
  }

  private fun endsWithHeaderTerminator(bytes: ByteArray): Boolean {
    val n = bytes.size
    if (n >= 4 &&
      bytes[n - 4] == '\r'.code.toByte() &&
      bytes[n - 3] == '\n'.code.toByte() &&
      bytes[n - 2] == '\r'.code.toByte() &&
      bytes[n - 1] == '\n'.code.toByte()
    ) {
      return true
    }
    if (n >= 2 && bytes[n - 2] == '\n'.code.toByte() && bytes[n - 1] == '\n'.code.toByte()) {
      return true
    }
    return false
  }
}
