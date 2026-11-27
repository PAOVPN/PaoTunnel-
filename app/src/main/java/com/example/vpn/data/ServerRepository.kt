package com.example.vpn.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.example.vpn.core.XrayCoreAdapterImpl
import com.example.vpn.model.VpnProtocol
import com.example.vpn.model.VpnServer
import com.example.vpn.parser.VpnLinkParser
import com.example.vpn.parser.XrayConfigBuilder
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request

private val Context.vpnDataStore: DataStore<Preferences> by preferencesDataStore(name = "pao_tunnel_prefs")

class ServerRepository(private val context: Context) {

  companion object {
    const val REMOTE_SERVERS_URL =
      "https://raw.githubusercontent.com/PAOVPN/PAO-TM-VPN/main/servers.json"

    private val KEY_REMOTE_SERVERS = stringPreferencesKey("remote_servers_json")
    private val KEY_CUSTOM_SERVERS = stringPreferencesKey("custom_servers_json")
    private val KEY_SELECTED_SERVER_ID = stringPreferencesKey("selected_server_id")
    private val KEY_LAST_UPDATED_MS = longPreferencesKey("last_updated_ms")
  }

  private val httpClient: OkHttpClient =
    OkHttpClient.Builder()
      .connectTimeout(15, TimeUnit.SECONDS)
      .readTimeout(20, TimeUnit.SECONDS)
      .followRedirects(true)
      .build()

  val remoteServersFlow: Flow<List<VpnServer>> =
    context.vpnDataStore.data.map { prefs ->
      VpnLinkParser.fromStorageJson(prefs[KEY_REMOTE_SERVERS].orEmpty())
    }

  val customServersFlow: Flow<List<VpnServer>> =
    context.vpnDataStore.data.map { prefs ->
      VpnLinkParser.fromStorageJson(prefs[KEY_CUSTOM_SERVERS].orEmpty())
    }

  val allServersFlow: Flow<List<VpnServer>> =
    combine(customServersFlow, remoteServersFlow) { custom, remote ->
      (custom + remote).distinctBy { it.id }
    }

  val selectedServerIdFlow: Flow<String?> =
    context.vpnDataStore.data.map { prefs -> prefs[KEY_SELECTED_SERVER_ID] }

  val lastUpdatedMsFlow: Flow<Long?> =
    context.vpnDataStore.data.map { prefs -> prefs[KEY_LAST_UPDATED_MS] }

  suspend fun updateServersFromRemote(): Result<Int> =
    withContext(Dispatchers.IO) {
      runCatching {
        val request =
          Request.Builder()
            .url(REMOTE_SERVERS_URL)
            .header("Accept", "application/json, text/plain, */*")
            .header("Cache-Control", "no-cache")
            .build()

        val body =
          httpClient.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
              error("Server list request failed (HTTP ${response.code})")
            }
            response.body?.string().orEmpty()
          }

        val parsed = VpnLinkParser.parseServersPayload(body)
        if (parsed.isEmpty()) {
          error("No valid VLESS or VMess servers found in remote servers.json")
        }

        val now = System.currentTimeMillis()
        context.vpnDataStore.edit { prefs ->
          prefs[KEY_REMOTE_SERVERS] = VpnLinkParser.toStorageJson(parsed)
          prefs[KEY_LAST_UPDATED_MS] = now
          val currentSelected = prefs[KEY_SELECTED_SERVER_ID]
          val customIds =
            VpnLinkParser.fromStorageJson(prefs[KEY_CUSTOM_SERVERS].orEmpty()).map { it.id }.toSet()
          if (currentSelected == null ||
            (parsed.none { it.id == currentSelected } && currentSelected !in customIds)
          ) {
            prefs[KEY_SELECTED_SERVER_ID] = parsed.first().id
          }
        }
        parsed.size
      }
    }

  suspend fun selectServer(serverId: String) {
    context.vpnDataStore.edit { prefs -> prefs[KEY_SELECTED_SERVER_ID] = serverId }
  }

  suspend fun addCustomServer(uri: String): Result<VpnServer> =
    withContext(Dispatchers.IO) {
      runCatching {
        val direct = VpnLinkParser.parseUri(uri, isCustom = true)
        if (direct != null) {
          saveCustomServer(direct)
          return@runCatching direct
        }
        val batch = VpnLinkParser.parseServersPayload(uri).map { it.copy(isCustom = true) }
        if (batch.isNotEmpty()) {
          batch.asReversed().forEach { saveCustomServer(it) }
          return@runCatching batch.first()
        }
        error("Invalid link or file. Please use a valid vless://, vmess://, ssh://, or paolock:// config.")
      }
    }

  suspend fun addSshServer(
    name: String,
    host: String,
    port: Int,
    username: String,
    password: String,
    payload: String,
    httpProxy: String = "",
    editingServerId: String? = null,
  ): Result<VpnServer> =
    withContext(Dispatchers.IO) {
      runCatching {
        val cleanHost = host.trim()
        val cleanUser = username.trim()
        require(cleanHost.isNotEmpty()) { "Host / IP is required." }
        require(port in 1..65535) { "Port must be between 1 and 65535." }
        require(cleanUser.isNotEmpty()) { "Username is required." }

        val parsedProxy =
          if (httpProxy.isBlank()) {
            "" to 0
          } else {
            VpnLinkParser.parseProxyString(httpProxy)
              ?: error("Invalid HTTP Proxy format. Use proxy_ip:proxy_port (e.g. 104.16.0.1:80).")
          }

        if (editingServerId != null) {
          val isTargetLocked =
            allServersFlow.first().any { it.id == editingServerId && it.isLocked }
          require(!isTargetLocked) { "Locked configs cannot be modified." }
        }

        val server =
          VpnLinkParser.createSshServer(
            name = name,
            host = cleanHost,
            port = port,
            username = cleanUser,
            password = password,
            payload = payload,
            sshProxyHost = parsedProxy.first,
            sshProxyPort = parsedProxy.second,
            isCustom = true,
          )
        saveCustomServer(server, replaceServerId = editingServerId)
        server
      }
    }

  private suspend fun saveCustomServer(server: VpnServer, replaceServerId: String? = null) {
    context.vpnDataStore.edit { prefs ->
      val existing = VpnLinkParser.fromStorageJson(prefs[KEY_CUSTOM_SERVERS].orEmpty())
      val filtered =
        existing.filterNot { it.id == server.id || (replaceServerId != null && it.id == replaceServerId) }
      val updated = listOf(server) + filtered
      prefs[KEY_CUSTOM_SERVERS] = VpnLinkParser.toStorageJson(updated)
      prefs[KEY_SELECTED_SERVER_ID] = server.id
    }
  }

  suspend fun deleteCustomServer(serverId: String) {
    context.vpnDataStore.edit { prefs ->
      val existing = VpnLinkParser.fromStorageJson(prefs[KEY_CUSTOM_SERVERS].orEmpty())
      val updated = existing.filterNot { it.id == serverId }
      prefs[KEY_CUSTOM_SERVERS] = VpnLinkParser.toStorageJson(updated)
      if (prefs[KEY_SELECTED_SERVER_ID] == serverId) {
        val remote = VpnLinkParser.fromStorageJson(prefs[KEY_REMOTE_SERVERS].orEmpty())
        val fallback = (updated + remote).firstOrNull()?.id
        if (fallback != null) {
          prefs[KEY_SELECTED_SERVER_ID] = fallback
        } else {
          prefs.remove(KEY_SELECTED_SERVER_ID)
        }
      }
    }
  }

  suspend fun updateServerLatency(serverId: String, latencyMs: Long?) {
    context.vpnDataStore.edit { prefs ->
      val remote = VpnLinkParser.fromStorageJson(prefs[KEY_REMOTE_SERVERS].orEmpty())
      if (remote.any { it.id == serverId }) {
        prefs[KEY_REMOTE_SERVERS] =
          VpnLinkParser.toStorageJson(
            remote.map { if (it.id == serverId) it.copy(latencyMs = latencyMs) else it }
          )
      }
      val custom = VpnLinkParser.fromStorageJson(prefs[KEY_CUSTOM_SERVERS].orEmpty())
      if (custom.any { it.id == serverId }) {
        prefs[KEY_CUSTOM_SERVERS] =
          VpnLinkParser.toStorageJson(
            custom.map { if (it.id == serverId) it.copy(latencyMs = latencyMs) else it }
          )
      }
    }
  }

  suspend fun measureServerLatency(server: VpnServer): Long? =
    withContext(Dispatchers.IO) {
      if (XrayCoreAdapterImpl.isRunning) {
        val delay = XrayCoreAdapterImpl.measureDelay()
        if (delay != null) return@withContext delay
      }
      if (server.protocol != VpnProtocol.SSH && XrayCoreAdapterImpl.isCoreAvailable) {
        val config = XrayConfigBuilder.buildConfig(server, enableTunInbound = false)
        val outboundDelay = XrayCoreAdapterImpl.measureOutboundDelay(config)
        if (outboundDelay != null) return@withContext outboundDelay
      }
      // Fallback: real TCP handshake latency to server host:port
      runCatching {
          val start = System.currentTimeMillis()
          Socket().use { socket ->
            socket.connect(InetSocketAddress(server.address, server.port), 3500)
          }
          (System.currentTimeMillis() - start).coerceAtLeast(1L)
        }
        .getOrNull()
    }

  suspend fun getServerById(serverId: String): VpnServer? {
    return allServersFlow.first().firstOrNull { it.id == serverId }
  }
}
