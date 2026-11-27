package com.example

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.ui.MainScreen
import com.example.ui.MainViewModel
import com.example.ui.theme.PaoTunnelTheme

class MainActivity : ComponentActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    enableEdgeToEdge(
      statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
      navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
    )
    setContent {
      PaoTunnelTheme {
        val viewModel: MainViewModel = viewModel()
        val uiState by viewModel.uiState.collectAsStateWithLifecycle()
        val context = LocalContext.current

        val vpnPermissionLauncher =
          rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
              viewModel.startSelectedVpn(context)
            }
          }

        val notificationPermissionLauncher =
          rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { _ ->
            val prepareIntent = VpnService.prepare(context)
            if (prepareIntent != null) {
              vpnPermissionLauncher.launch(prepareIntent)
            } else {
              viewModel.startSelectedVpn(context)
            }
          }

        val initiateVpnConnect = {
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) !=
              PackageManager.PERMISSION_GRANTED
          ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
          } else {
            val prepareIntent = VpnService.prepare(context)
            if (prepareIntent != null) {
              vpnPermissionLauncher.launch(prepareIntent)
            } else {
              viewModel.startSelectedVpn(context)
            }
          }
        }

        MainScreen(
          uiState = uiState,
          onUpdateServers = { viewModel.updateServers() },
          onSelectServer = { server -> viewModel.selectServer(server, context) },
          onPingSelected = { viewModel.pingSelectedServer() },
          onConnectClick = initiateVpnConnect,
          onDisconnectClick = { viewModel.disconnectVpn(context) },
          onOpenImportDialog = { viewModel.openImportDialog() },
          onEditSshServer = { server -> viewModel.openEditSshDialog(server) },
          onCloseImportDialog = { viewModel.closeImportDialog() },
          onImportLink = { link -> viewModel.importCustomServer(link) },
          onAddSshServer = { name, host, port, username, password, payload, httpProxy, editingId ->
            viewModel.addSshServer(
              name = name,
              host = host,
              port = port,
              username = username,
              password = password,
              payload = payload,
              httpProxy = httpProxy,
              editingServerId = editingId,
            )
          },
          onDeleteCustomServer = { id -> viewModel.deleteCustomServer(id) },
          onShowMessage = { msg -> viewModel.showBannerMessage(msg) },
          onDismissMessage = { viewModel.dismissBannerMessage() },
        )
      }
    }
  }
}
