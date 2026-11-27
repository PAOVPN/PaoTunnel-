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

  @Test
  fun configCrypto_encryptsServerWithAesGcmAndDecryptsAsLockedWithoutLeakingSecrets() {
    val sshServer =
      com.example.vpn.model.VpnServer(
        id = "orig-1",
        name = "Dtac 🇹🇭",
        protocol = com.example.vpn.model.VpnProtocol.SSH,
        address = "157.85.103.29",
        port = 22,
        username = "Admin",
        password = "UltraSecretPassword#99",
        payload = "CONNECT [host_port] [protocol][crlf][crlf][split]PATCH / HTTP/1.1[crlf]Host: bug.dtac.th[crlf][crlf]",
        sshProxyHost = "104.18.57.37",
        sshProxyPort = 80,
        isCustom = true,
        isLocked = false,
      )

    val encryptedLink = com.example.vpn.crypto.ConfigCrypto.encryptServerToLink(sshServer)
    assertTrue(encryptedLink.startsWith("paolock://"))
    // Must not expose any sensitive fields in plaintext inside the link
    assertTrue(!encryptedLink.contains("157.85.103.29"))
    assertTrue(!encryptedLink.contains("Admin"))
    assertTrue(!encryptedLink.contains("UltraSecretPassword"))
    assertTrue(!encryptedLink.contains("104.18.57.37"))
    assertTrue(!encryptedLink.contains("bug.dtac.th"))

    val decrypted = com.example.vpn.crypto.ConfigCrypto.decryptLinkToServer(encryptedLink, isCustom = true)!!
    assertTrue(decrypted.isLocked)
    assertTrue(decrypted.isCustom)
    assertEquals("Dtac 🇹🇭", decrypted.name)
    assertEquals("157.85.103.29", decrypted.address)
    assertEquals(22, decrypted.port)
    assertEquals("Admin", decrypted.username)
    assertEquals("UltraSecretPassword#99", decrypted.password)
    assertEquals("104.18.57.37", decrypted.sshProxyHost)
    assertEquals(80, decrypted.sshProxyPort)
    assertEquals(sshServer.payload, decrypted.payload)
    assertEquals("SSH • Protected Config", decrypted.homeDisplaySubtitle)
    assertEquals(encryptedLink, decrypted.rawUri)

    // Verify AES-GCM integrity check rejects tampered links (both mid-ciphertext and trailing)
    val midIdx = encryptedLink.length / 2
    val midChar = encryptedLink[midIdx]
    val tamperedMidChar = if (midChar == 'A') 'B' else 'A'
    val tamperedMidLink = encryptedLink.substring(0, midIdx) + tamperedMidChar + encryptedLink.substring(midIdx + 1)
    assertEquals(null, com.example.vpn.crypto.ConfigCrypto.decryptLinkToServer(tamperedMidLink))

    val lastChar = encryptedLink.last()
    val tamperedChar = if (lastChar == 'A') 'B' else 'A'
    val tamperedLink = encryptedLink.dropLast(1) + tamperedChar
    assertEquals(null, com.example.vpn.crypto.ConfigCrypto.decryptLinkToServer(tamperedLink))
  }

  @Test
  fun vpnServer_homeDisplaySubtitleHidesIpHostAndCredentials() {
    val vlessServer =
      com.example.vpn.model.VpnServer(
        id = "v1",
        name = "SG VLESS",
        protocol = com.example.vpn.model.VpnProtocol.VLESS,
        address = "45.32.100.10",
        port = 443,
        uuid = "11111111-2222-3333-4444-555555555555",
      )
    assertEquals("V2Ray • Protected", vlessServer.homeDisplaySubtitle)
  }

  @Test
  fun slowDns_commandBuilderAndAesLockPreserveAllFieldsAndMaskSubtitle() {
    val pubKey = "a".repeat(64)
    val slowDnsServer =
      com.example.vpn.model.VpnServer(
        id = "sd-1",
        name = "MM SlowDNS",
        protocol = com.example.vpn.model.VpnProtocol.SSH,
        address = "127.0.0.1",
        port = 22,
        username = "pao_dns_user",
        password = "dns_secret_pw",
        sshTunnelMode = com.example.vpn.model.SshTunnelMode.SLOW_DNS,
        slowDnsServerIp = "1.1.1.1",
        slowDnsNameserver = "://ns1.example.com",
        slowDnsPublicKey = pubKey,
        isCustom = true,
      )

    assertTrue(slowDnsServer.isSlowDns)
    assertEquals("SlowDNS • Protected Config", slowDnsServer.homeDisplaySubtitle)

    val cmd =
      com.example.vpn.ssh.SlowDnsManager.buildCommand(
        "/data/app/lib/arm64/libdnstt.so",
        slowDnsServer,
      )
    assertEquals(
      listOf(
        "/data/app/lib/arm64/libdnstt.so",
        "-udp",
        "1.1.1.1:53",
        "-pubkey",
        pubKey,
        "ns1.example.com",
        "127.0.0.1:7000",
      ),
      cmd,
    )

    val lockedLink = com.example.vpn.crypto.ConfigCrypto.encryptServerToLink(slowDnsServer)
    assertTrue(lockedLink.startsWith("paolock://"))
    assertTrue(!lockedLink.contains("1.1.1.1"))
    assertTrue(!lockedLink.contains("ns1.example.com"))
    assertTrue(!lockedLink.contains(pubKey))
    assertTrue(!lockedLink.contains("pao_dns_user"))

    val decrypted = com.example.vpn.crypto.ConfigCrypto.decryptLinkToServer(lockedLink)!!
    assertTrue(decrypted.isLocked)
    assertTrue(decrypted.isSlowDns)
    assertEquals(com.example.vpn.model.SshTunnelMode.SLOW_DNS, decrypted.sshTunnelMode)
    assertEquals("1.1.1.1", decrypted.slowDnsServerIp)
    assertEquals("://ns1.example.com", decrypted.slowDnsNameserver)
    assertEquals(pubKey, decrypted.slowDnsPublicKey)
    assertEquals("SlowDNS • Protected Config", decrypted.homeDisplaySubtitle)
  }

  @Test
  fun udpZivpn_configJsonUriParsingAndAesLockPreserveAllFields() {
    val parsedDefault =
      com.example.vpn.parser.VpnLinkParser.parseUri(
        "udp://zivpn_pw@157.85.103.29?window=3#SG%20ZIVPN",
        isCustom = true,
      )!!

    assertEquals(com.example.vpn.model.VpnProtocol.UDP, parsedDefault.protocol)
    assertEquals("SG ZIVPN", parsedDefault.name)
    assertEquals("157.85.103.29", parsedDefault.address)
    assertEquals("6000-19999", parsedDefault.effectiveUdpPortRange)
    assertEquals(6000, parsedDefault.port)
    assertEquals("zivpn_pw", parsedDefault.password)
    assertEquals(3, parsedDefault.udpReceiveWindow)
    assertEquals("UDP • Protected Config", parsedDefault.homeDisplaySubtitle)

    val parsedCustomRange =
      com.example.vpn.parser.VpnLinkParser.parseUri(
        "udp://my_pass@45.32.1.2:7000-15000?window=2#Custom%20UDP",
        isCustom = false,
      )!!
    assertEquals("7000-15000", parsedCustomRange.effectiveUdpPortRange)
    assertEquals(7000, parsedCustomRange.port)
    assertEquals(2, parsedCustomRange.udpReceiveWindow)

    val configJson = com.example.vpn.udp.HysteriaUdpManager.buildConfigJson(parsedCustomRange)
    assertTrue(configJson.contains("\"server\": \"45.32.1.2:7000-15000\""))
    assertTrue(configJson.contains("\"protocol\": \"udp\""))
    assertTrue(configJson.contains("\"auth_str\": \"my_pass\""))
    assertTrue(configJson.contains("\"obfs\": \"my_pass\""))
    assertTrue(configJson.contains("\"recv_window_conn\": 2097152"))
    assertTrue(configJson.contains("\"recv_window\": 5242880"))
    assertTrue(configJson.contains("\"insecure\": true"))
    assertTrue(configJson.contains("\"listen\": \"127.0.0.1:10809\""))

    val cmd =
      com.example.vpn.udp.HysteriaUdpManager.buildCommand(
        "/data/app/lib/arm64/libhysteria.so",
        "/data/user/0/app/files/hysteria_udp_config.json",
      )
    assertEquals(
      listOf(
        "/data/app/lib/arm64/libhysteria.so",
        "client",
        "--no-check",
        "-c",
        "/data/user/0/app/files/hysteria_udp_config.json",
      ),
      cmd,
    )

    val lockedLink = com.example.vpn.crypto.ConfigCrypto.encryptServerToLink(parsedCustomRange)
    assertTrue(lockedLink.startsWith("paolock://"))
    assertTrue(!lockedLink.contains("45.32.1.2"))
    assertTrue(!lockedLink.contains("my_pass"))
    assertTrue(!lockedLink.contains("7000-15000"))

    val decrypted = com.example.vpn.crypto.ConfigCrypto.decryptLinkToServer(lockedLink)!!
    assertTrue(decrypted.isLocked)
    assertEquals(com.example.vpn.model.VpnProtocol.UDP, decrypted.protocol)
    assertEquals("45.32.1.2", decrypted.address)
    assertEquals("7000-15000", decrypted.effectiveUdpPortRange)
    assertEquals("my_pass", decrypted.password)
    assertEquals(2, decrypted.udpReceiveWindow)
    assertEquals("UDP • Protected Config", decrypted.homeDisplaySubtitle)
  }
}
