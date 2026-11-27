package com.example

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import com.example.vpn.model.VpnProtocol
import com.example.vpn.parser.VpnLinkParser
import com.example.vpn.parser.XrayConfigBuilder
import java.nio.charset.StandardCharsets
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleRobolectricTest {

  @Test
  fun `read app name string from context`() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val appName = context.getString(R.string.app_name)
    assertEquals("PAO Tunnel", appName)
  }

  @Test
  fun `parse vless reality link and generate valid xray config`() {
    val uri =
      "vless://11111111-2222-3333-4444-555555555555@sg.example.com:443?encryption=none&security=reality&sni=www.google.com&fp=chrome&pbk=testPublicKey&sid=abcd&type=tcp&flow=xtls-rprx-vision#SG%20Node"
    val server = VpnLinkParser.parseUri(uri, isCustom = true)
    assertNotNull(server)
    server!!
    assertEquals("SG Node", server.name)
    assertEquals(VpnProtocol.VLESS, server.protocol)
    assertEquals("sg.example.com", server.address)
    assertEquals(443, server.port)
    assertEquals("reality", server.tlsMode)
    assertEquals("xtls-rprx-vision", server.flow)

    val config = JSONObject(XrayConfigBuilder.buildConfig(server, enableTunInbound = true))
    val outbounds = config.getJSONArray("outbounds")
    assertEquals("vless", outbounds.getJSONObject(0).getString("protocol"))
    assertEquals("tun", config.getJSONArray("inbounds").getJSONObject(0).getString("protocol"))
  }

  @Test
  fun `parse vmess link and servers json formats`() {
    val vmessJson =
      JSONObject()
        .apply {
          put("v", "2")
          put("ps", "JP Tokyo WS")
          put("add", "jp.example.com")
          put("port", "443")
          put("id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
          put("aid", "0")
          put("net", "ws")
          put("type", "none")
          put("host", "cdn.example.com")
          put("path", "/ws")
          put("tls", "tls")
        }
        .toString()
    val vmessLink =
      "vmess://" +
        Base64.encodeToString(vmessJson.toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP)

    val serversPayload =
      """
      {
        "servers": [
          {"name": "Tokyo Custom", "url": "$vmessLink"},
          {"name": "US Direct", "protocol": "vless", "address": "us.example.com", "port": 8443, "id": "12345678-1234-1234-1234-123456789012", "network": "ws", "security": "tls", "sni": "us.example.com", "path": "/vless"}
        ]
      }
      """
        .trimIndent()

    val parsed = VpnLinkParser.parseServersPayload(serversPayload)
    assertEquals(2, parsed.size)
    assertEquals("Tokyo Custom", parsed[0].name)
    assertEquals(VpnProtocol.VMESS, parsed[0].protocol)
    assertEquals("ws", parsed[0].network)
    assertEquals("US Direct", parsed[1].name)
    assertEquals(VpnProtocol.VLESS, parsed[1].protocol)
    assertTrue(XrayConfigBuilder.buildConfig(parsed[0]).contains("\"protocol\": \"vmess\""))
  }

  @Test
  fun `build valid xray configs for port 80 plain vless and port 443 tls vless`() {
    val port80Uri =
      "vless://11111111-2222-3333-4444-555555555555@example.com:80?encryption=none&security=none&type=ws&host=example.com&path=%2Fws#Port80"
    val port443Uri =
      "vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&host=example.com&path=%2Fws#Port443"

    val s80 = VpnLinkParser.parseUri(port80Uri)!!
    val s443 = VpnLinkParser.parseUri(port443Uri)!!

    val cfg80 = JSONObject(XrayConfigBuilder.buildConfig(s80))
    val outbound80 = cfg80.getJSONArray("outbounds").getJSONObject(0)
    val vnext80 = outbound80.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
    assertEquals("example-com.local", vnext80.getString("address"))
    assertEquals("example.com", cfg80.getJSONObject("dns").getJSONObject("hosts").getString("example-com.local"))
    val stream80 = outbound80.getJSONObject("streamSettings")
    assertEquals("none", stream80.getString("security"))
    assertEquals("UseIP", stream80.getJSONObject("sockopt").getString("domainStrategy"))
    assertFalse(stream80.has("tlsSettings"))

    val cfg443 = JSONObject(XrayConfigBuilder.buildConfig(s443))
    val stream443 = cfg443.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
    assertEquals("tls", stream443.getString("security"))
    assertFalse(stream443.getJSONObject("tlsSettings").has("allowInsecure"))
  }

  @Test
  fun `convert public ipv4 address to private local domain when vless security is none or empty and map dns hosts`() {
    val ipPort80Uri =
      "vless://11111111-2222-3333-4444-555555555555@157.85.103.29:80?encryption=none&security=&type=ws&host=bug.example.com&path=%2Fws#IP80"
    val ipPort443Uri =
      "vless://11111111-2222-3333-4444-555555555555@157.85.103.29:443?encryption=none&security=tls&sni=bug.example.com&type=ws&host=bug.example.com&path=%2Fws#IP443"

    val s80 = VpnLinkParser.parseUri(ipPort80Uri)!!
    assertEquals("none", s80.tlsMode)
    val cfg80 = JSONObject(XrayConfigBuilder.buildConfig(s80))
    val dnsHosts80 = cfg80.getJSONObject("dns").getJSONObject("hosts")
    assertEquals("157.85.103.29", dnsHosts80.getString("157-85-103-29.local"))

    val outbound80 = cfg80.getJSONArray("outbounds").getJSONObject(0)
    val vnext80 = outbound80.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
    assertEquals("157-85-103-29.local", vnext80.getString("address"))
    val stream80 = outbound80.getJSONObject("streamSettings")
    assertEquals("UseIP", stream80.getJSONObject("sockopt").getString("domainStrategy"))
    val wsHost80 = stream80.getJSONObject("wsSettings").getJSONObject("headers").getString("Host")
    assertEquals("bug.example.com", wsHost80)

    val s443 = VpnLinkParser.parseUri(ipPort443Uri)!!
    val cfg443 = JSONObject(XrayConfigBuilder.buildConfig(s443))
    assertFalse(cfg443.getJSONObject("dns").has("hosts"))
    val vnext443 =
      cfg443
        .getJSONArray("outbounds")
        .getJSONObject(0)
        .getJSONObject("settings")
        .getJSONArray("vnext")
        .getJSONObject(0)
    assertEquals("157.85.103.29", vnext443.getString("address"))
  }
}
