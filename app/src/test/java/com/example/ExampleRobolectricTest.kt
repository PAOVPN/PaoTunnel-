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
}
