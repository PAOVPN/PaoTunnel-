package com.example.ui

import android.app.Application
import android.content.Context
import androidx.compose.runtime.Immutable
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.vpn.data.ServerRepository
import com.example.vpn.model.VpnConnectionState
import com.example.vpn.model.VpnRuntimeState
import com.example.vpn.model.VpnServer
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
data class MainUiState(
  val servers: List<VpnServer> = emptyList(),
  val selectedServer: VpnServer? = null,
  val runtimeState: VpnRuntimeState = VpnRuntimeState(),
  val isUpdatingServers: Boolean = false,
  val isPinging: Boolean = false,
  val lastUpdatedMs: Long? = null,
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
    val statusBannerMessage: String? = null,
    val showImportDialog: Boolean = false,
    val editingServer: VpnServer? = null,
    val exportingServer: VpnServer? = null,
  )

  private val transientState = MutableStateFlow(TransientUiState())

  val uiState: StateFlow<MainUiState> =
    combine(
        repository.allServersFlow,
        repository.selectedServerIdFlow,
        repository.lastUpdatedMsFlow,
        VpnStateHolder.state,
        transientState,
      ) { servers, selectedId, lastUpdatedMs, runtime, transient ->
        val selected = servers.firstOrNull { it.id == selectedId } ?: servers.firstOrNull()
        MainUiState(
          servers = servers,
          selectedServer = selected,
          runtimeState = runtime,
          isUpdatingServers = transient.isUpdatingServers,
          isPinging = transient.isPinging,
          lastUpdatedMs = lastUpdatedMs,
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

  fun updateServers() {
    if (transientState.value.isUpdatingServers) return
    viewModelScope.launch {
      transientState.update { it.copy(isUpdatingServers = true, statusBannerMessage = null) }
      repository
        .updateServersFromRemote()
        .onSuccess { count ->
          transientState.update {
            it.copy(
              isUpdatingServers = false,
              statusBannerMessage = "Updated $count servers from repository.",
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

  fun selectServer(server: VpnServer, context: Context) {
    viewModelScope.launch {
      repository.selectServer(server.id)
      val currentRuntime = VpnStateHolder.state.value
      if (currentRuntime.connectionState == VpnConnectionState.CONNECTED &&
        currentRuntime.activeServerId != server.id
      ) {
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

  fun openEditSshDialog(server: VpnServer) {
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
          editingServerId = editingServerId,
        )
        .onSuccess { server ->
          transientState.update {
            it.copy(
              showImportDialog = false,
              editingServer = null,
              statusBannerMessage =
                if (editingServerId != null) {
                  "Updated SSH Server: ${server.name}"
                } else {
                  "Added SSH Server: ${server.name}"
                },
            )
          }
        }
        .onFailure { error ->
          transientState.update {
            it.copy(statusBannerMessage = error.message ?: "Invalid SSH server settings.")
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
