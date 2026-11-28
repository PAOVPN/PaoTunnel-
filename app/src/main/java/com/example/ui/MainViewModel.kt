package com.example.ui

import android.app.Application
import android.content.Context
import androidx.compose.runtime.Immutable
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.vpn.data.ServerRepository
import com.example.vpn.model.SshTunnelMode
import com.example.vpn.model.VpnConnectionState
import com.example.vpn.model.VpnRuntimeState
import com.example.vpn.model.VpnServer
import com.example.vpn.security.SecurityGuard
import com.example.vpn.security.SecurityThreat
import com.example.vpn.service.VpnStateHolder
import com.example.vpn.service.XrayVpnService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

@Immutable
data class VersionUpdateNotice(
  val version: Int,
  val notice: String,
  val serverCount: Int,
)

@Immutable
data class MainUiState(
  val servers: List<VpnServer> = emptyList(),
  val selectedServer: VpnServer? = null,
  val runtimeState: VpnRuntimeState = VpnRuntimeState(),
  val isUpdatingServers: Boolean = false,
  val isPinging: Boolean = false,
  val lastUpdatedMs: Long? = null,
  val remoteVersion: Int = 0,
  val remoteNotice: String = "",
  val versionUpdateDialog: VersionUpdateNotice? = null,
  val securityWarning: SecurityThreat? = null,
  val statusBannerMessage: String? = null,
  val showImportDialog: Boolean = false,
  val editingServer: VpnServer? = null,
  val exportingServer: VpnServer? = null,
)

class MainViewModel(application: Application) : AndroidViewModel(application) {

  private val repository = ServerRepository(application.applicationContext)

  private data class TransientUiState(
    val isUpdatingServers: Boolean = false,
    val isPinging: Boolean = false,
    val versionUpdateDialog: VersionUpdateNotice? = null,
    val securityWarning: SecurityThreat? = null,
    val statusBannerMessage: String? = null,
    val showImportDialog: Boolean = false,
    val editingServer: VpnServer? = null,
    val exportingServer: VpnServer? = null,
  )

  private val transientState = MutableStateFlow(TransientUiState())

  private val syncMetadataFlow =
    combine(
      repository.lastUpdatedMsFlow,
      repository.remoteVersionFlow,
      repository.remoteNoticeFlow,
    ) { lastUpdatedMs, version, notice ->
      Triple(lastUpdatedMs, version, notice)
    }

  val uiState: StateFlow<MainUiState> =
    combine(
        repository.allServersFlow,
        repository.selectedServerIdFlow,
        syncMetadataFlow,
        VpnStateHolder.state,
        transientState,
      ) { servers, selectedId, syncMeta, runtime, transient ->
        val selected = servers.firstOrNull { it.id == selectedId } ?: servers.firstOrNull()
        MainUiState(
          servers = servers,
          selectedServer = selected,
          runtimeState = runtime,
          isUpdatingServers = transient.isUpdatingServers,
          isPinging = transient.isPinging,
          lastUpdatedMs = syncMeta.first,
          remoteVersion = syncMeta.second,
          remoteNotice = syncMeta.third,
          versionUpdateDialog = transient.versionUpdateDialog,
          securityWarning = transient.securityWarning,
          statusBannerMessage = transient.statusBannerMessage,
          showImportDialog = transient.showImportDialog,
          editingServer = transient.editingServer,
          exportingServer = transient.exportingServer,
        )
      }
      .stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = MainUiState(runtimeState = VpnStateHolder.state.value),
      )

  init {
    autoSyncOnLaunch()
  }

  private fun autoSyncOnLaunch() {
    viewModelScope.launch {
      val currentConnection = VpnStateHolder.state.value.connectionState
      if (currentConnection != VpnConnectionState.DISCONNECTED &&
        currentConnection != VpnConnectionState.ERROR
      ) {
        return@launch
      }
      if (!repository.hasInternetConnectivity()) {
        return@launch
      }
      if (transientState.value.isUpdatingServers) return@launch

      transientState.update { it.copy(isUpdatingServers = true) }
      repository
        .updateServersFromRemote()
        .onSuccess { outcome ->
          transientState.update { state ->
            state.copy(
              isUpdatingServers = false,
              versionUpdateDialog =
                if (outcome.isNewVersion) {
                  VersionUpdateNotice(
                    version = outcome.version,
                    notice = outcome.notice,
                    serverCount = outcome.serverCount,
                  )
                } else {
                  state.versionUpdateDialog
                },
            )
          }
        }
        .onFailure {
          // Offline / unreachable: silently continue using cached local servers
          transientState.update { it.copy(isUpdatingServers = false) }
        }
    }
  }

  fun updateServers() {
    if (transientState.value.isUpdatingServers) return
    viewModelScope.launch {
      transientState.update { it.copy(isUpdatingServers = true, statusBannerMessage = null) }
      repository
        .updateServersFromRemote()
        .onSuccess { outcome ->
          transientState.update { state ->
            state.copy(
              isUpdatingServers = false,
              statusBannerMessage = "Updated ${outcome.serverCount} servers from repository.",
              versionUpdateDialog =
                if (outcome.isNewVersion) {
                  VersionUpdateNotice(
                    version = outcome.version,
                    notice = outcome.notice,
                    serverCount = outcome.serverCount,
                  )
                } else {
                  state.versionUpdateDialog
                },
            )
          }
        }
        .onFailure { error ->
          transientState.update {
            it.copy(
              isUpdatingServers = false,
              statusBannerMessage = error.message ?: "Failed to fetch servers.",
            )
          }
        }
    }
  }

  fun dismissVersionUpdateDialog(version: Int) {
    transientState.update { it.copy(versionUpdateDialog = null) }
    viewModelScope.launch { repository.markVersionSeen(version) }
  }

  fun verifySecurityBeforeConnect(context: Context): Boolean {
    val threat = SecurityGuard.inspectDevice(context.applicationContext) ?: return true
    transientState.update {
      it.copy(
        securityWarning = threat,
        statusBannerMessage = threat.message,
      )
    }
    return false
  }

  fun dismissSecurityWarning() {
    transientState.update { it.copy(securityWarning = null) }
  }

  fun selectServer(server: VpnServer, context: Context) {
    viewModelScope.launch {
      repository.selectServer(server.id)
      val currentRuntime = VpnStateHolder.state.value
      if (currentRuntime.connectionState == VpnConnectionState.CONNECTED &&
        currentRuntime.activeServerId != server.id
      ) {
        if (!verifySecurityBeforeConnect(context)) {
          XrayVpnService.stopVpn(context.applicationContext)
          return@launch
        }
        XrayVpnService.startVpn(context.applicationContext, server)
      }
    }
  }

  fun pingSelectedServer() {
    val server = uiState.value.selectedServer ?: return
    if (transientState.value.isPinging) return
    viewModelScope.launch {
      transientState.update { it.copy(isPinging = true) }
      val latency = repository.measureServerLatency(server)
      repository.updateServerLatency(server.id, latency)
      transientState.update {
        it.copy(
          isPinging = false,
          statusBannerMessage =
            if (latency != null) {
              "${server.name}: ${latency} ms"
            } else {
              "Server timed out during latency check."
            },
        )
      }
    }
  }

  fun openImportDialog() {
    transientState.update { it.copy(showImportDialog = true, editingServer = null) }
  }

  fun openEditServerDialog(server: VpnServer) {
    if (server.isLocked) {
      transientState.update { it.copy(statusBannerMessage = "Locked configs cannot be edited.") }
      return
    }
    transientState.update { it.copy(showImportDialog = true, editingServer = server) }
  }

  fun closeImportDialog() {
    transientState.update { it.copy(showImportDialog = false, editingServer = null) }
  }

  fun openExportDialog(server: VpnServer) {
    if (server.isLocked) {
      transientState.update { it.copy(statusBannerMessage = "Locked configs cannot be shared or exported.") }
      return
    }
    transientState.update { it.copy(exportingServer = server) }
  }

  fun closeExportDialog() {
    transientState.update { it.copy(exportingServer = null) }
  }

  fun importCustomServer(rawLink: String) {
    viewModelScope.launch {
      repository
        .addCustomServer(rawLink)
        .onSuccess { server ->
          val lockTag = if (server.isLocked) " (Locked)" else ""
          transientState.update {
            it.copy(
              showImportDialog = false,
              editingServer = null,
              statusBannerMessage = "Imported ${server.protocol.displayName}$lockTag: ${server.name}",
            )
          }
        }
        .onFailure { error ->
          transientState.update {
            it.copy(statusBannerMessage = error.message ?: "Invalid VLESS, VMess, SSH, or locked link.")
          }
        }
    }
  }

  fun addSshServer(
    name: String,
    host: String,
    port: Int,
    username: String,
    password: String,
    payload: String,
    httpProxy: String,
    sshTunnelMode: SshTunnelMode,
    slowDnsServerIp: String,
    slowDnsNameserver: String,
    slowDnsPublicKey: String,
    editingServerId: String?,
  ) {
    viewModelScope.launch {
      repository
        .addSshServer(
          name = name,
          host = host,
          port = port,
          username = username,
          password = password,
          payload = payload,
          httpProxy = httpProxy,
          sshTunnelMode = sshTunnelMode,
          slowDnsServerIp = slowDnsServerIp,
          slowDnsNameserver = slowDnsNameserver,
          slowDnsPublicKey = slowDnsPublicKey,
          editingServerId = editingServerId,
        )
        .onSuccess { server ->
          val label = if (server.isSlowDns) "SlowDNS" else "SSH"
          transientState.update {
            it.copy(
              showImportDialog = false,
              editingServer = null,
              statusBannerMessage =
                if (editingServerId != null) {
                  "Updated $label Server: ${server.name}"
                } else {
                  "Added $label Server: ${server.name}"
                },
            )
          }
        }
        .onFailure { error ->
          transientState.update {
            it.copy(statusBannerMessage = error.message ?: "Invalid SSH / SlowDNS server settings.")
          }
        }
    }
  }

  fun showBannerMessage(message: String) {
    transientState.update { it.copy(statusBannerMessage = message) }
  }

  fun deleteCustomServer(serverId: String) {
    viewModelScope.launch { repository.deleteCustomServer(serverId) }
  }

  fun startSelectedVpn(context: Context) {
    if (!verifySecurityBeforeConnect(context)) {
      return
    }
    val server = uiState.value.selectedServer
    if (server == null) {
      transientState.update {
        it.copy(statusBannerMessage = "Please tap Update Servers or import a server first.")
      }
      return
    }
    VpnStateHolder.clearError()
    XrayVpnService.startVpn(context.applicationContext, server)
  }

  fun disconnectVpn(context: Context) {
    XrayVpnService.stopVpn(context.applicationContext)
  }

  fun dismissBannerMessage() {
    transientState.update { it.copy(statusBannerMessage = null) }
    VpnStateHolder.clearError()
  }
}
