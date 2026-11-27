package com.example

import com.example.vpn.ssh.PayloadSocketFactory
import com.example.vpn.ssh.SshPayloadHelper
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.PushbackInputStream
import java.nio.charset.StandardCharsets
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ExampleUnitTest {

  @Test
  fun formatPayload_translatesAllNetModTagsAndEscapes() {
    val raw =
      "CONNECT [host_port] [protocol][crlf][crlf]" +
        "PATCH / [protocol]\\r\\nHost: [host]\\r\\nPort: [port]\\r\\nUser-Agent: [ua][lf]X-Cr: 1[cr][crlf][crlf]"

    val formatted = SshPayloadHelper.formatPayload(raw, "157.85.103.29", 443)

    val expectedFirst = "CONNECT 157.85.103.29:443 HTTP/1.1\r\n\r\n"
    val expectedSecond =
      "PATCH / HTTP/1.1\r\n" +
        "Host: 157.85.103.29\r\n" +
        "Port: 443\r\n" +
        "User-Agent: Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36\n" +
        "X-Cr: 1\r\r\n\r\n"

    assertEquals(expectedFirst + expectedSecond, formatted)
  }

  @Test
  fun splitSegments_handlesSplitTagAndConcatenatedDoubleRequestsWith100msDelay() {
    val explicitSplit =
      SshPayloadHelper.formatPayload(
        "CONNECT [host_port] [protocol][crlf][crlf][split]GET / [protocol][crlf]Host: bug.com[crlf][crlf]",
        "10.0.0.1",
        443,
      )
    val explicitSegments = SshPayloadHelper.splitSegments(explicitSplit)
    assertEquals(2, explicitSegments.size)
    assertEquals(100L, explicitSegments[0].delayAfterMs)
    assertEquals("CONNECT 10.0.0.1:443 HTTP/1.1\r\n\r\n", String(explicitSegments[0].bytes, StandardCharsets.UTF_8))
    assertEquals("GET / HTTP/1.1\r\nHost: bug.com\r\n\r\n", String(explicitSegments[1].bytes, StandardCharsets.UTF_8))

    val doubleRequestWithoutSplitTag =
      SshPayloadHelper.formatPayload(
        "CONNECT [host_port] [protocol][crlf][crlf]PATCH / [protocol][crlf]Host: bug.com[crlf]Upgrade: websocket[crlf][crlf]",
        "10.0.0.1",
        443,
      )
    val autoSegments = SshPayloadHelper.splitSegments(doubleRequestWithoutSplitTag)
    assertEquals(2, autoSegments.size)
    assertEquals(100L, autoSegments[0].delayAfterMs)
    assertEquals("CONNECT 10.0.0.1:443 HTTP/1.1\r\n\r\n", String(autoSegments[0].bytes, StandardCharsets.UTF_8))
    assertEquals(
      "PATCH / HTTP/1.1\r\nHost: bug.com\r\nUpgrade: websocket\r\n\r\n",
      String(autoSegments[1].bytes, StandardCharsets.UTF_8),
    )
  }

  @Test
  fun consumeHttpUpgradeResponses_tolerates400WithBodyThenConsumes101AndPreservesSshBanner() {
    val errorBody = "<html><a href=\"http://cf.test\">400 Bad Request</a></html>"
    val wireData =
      "HTTP/1.1 400 Bad Request\r\nServer: cloudflare\r\nContent-Length: ${errorBody.length}\r\n\r\n" +
        errorBody +
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" +
        "SSH-2.0-OpenSSH_8.9p1\r\n"

    val input = PushbackInputStream(ByteArrayInputStream(wireData.toByteArray(StandardCharsets.US_ASCII)), 16 * 1024)
    PayloadSocketFactory(rawPayload = "").consumeHttpUpgradeResponses(
      socket = null,
      input = input,
      expectedRequests = 2,
    )

    val remaining = input.readBytes().toString(StandardCharsets.US_ASCII)
    assertEquals("SSH-2.0-OpenSSH_8.9p1\r\n", remaining)
  }

  @Test
  fun consumeHttpUpgradeResponses_toleratesUnframed400BodyContainingHttpUrlThenConsumes101() {
    val wireData =
      "HTTP/1.1 400 Bad Request\r\nServer: cloudflare\r\n\r\n" +
        "<html><a href=\"http://cloudflare.com\">400</a></html>" +
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n" +
        "SSH-2.0-dropbear_2022.83\r\n"

    val input = PushbackInputStream(ByteArrayInputStream(wireData.toByteArray(StandardCharsets.US_ASCII)), 16 * 1024)
    PayloadSocketFactory(rawPayload = "").consumeHttpUpgradeResponses(
      socket = null,
      input = input,
      expectedRequests = 2,
    )

    val remaining = input.readBytes().toString(StandardCharsets.US_ASCII)
    assertEquals("SSH-2.0-dropbear_2022.83\r\n", remaining)
  }

  @Test
  fun consumeHttpUpgradeResponses_handles200OkFollowedDirectlyBySshBanner() {
    val wireData =
      "HTTP/1.1 200 Connection established\r\n\r\n" +
        "SSH-2.0-OpenSSH_9.0\r\n"

    val input = PushbackInputStream(ByteArrayInputStream(wireData.toByteArray(StandardCharsets.US_ASCII)), 16 * 1024)
    PayloadSocketFactory(rawPayload = "").consumeHttpUpgradeResponses(
      socket = null,
      input = input,
      expectedRequests = 2,
    )

    val remaining = input.readBytes().toString(StandardCharsets.US_ASCII)
    assertEquals("SSH-2.0-OpenSSH_9.0\r\n", remaining)
  }

  @Test
  fun consumeHttpUpgradeResponses_throwsWhenOnlyErrorStatusReturned() {
    val wireData = "HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden"
    val input = PushbackInputStream(ByteArrayInputStream(wireData.toByteArray(StandardCharsets.US_ASCII)), 16 * 1024)

    val ex =
      assertThrows(IOException::class.java) {
        PayloadSocketFactory(rawPayload = "").consumeHttpUpgradeResponses(
          socket = null,
          input = input,
          expectedRequests = 1,
        )
      }
    assertTrue(ex.message.orEmpty().contains("403 Forbidden"))
  }
}
