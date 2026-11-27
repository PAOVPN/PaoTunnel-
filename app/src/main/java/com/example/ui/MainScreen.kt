package com.example.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AddLink
import androidx.compose.material.icons.rounded.ArrowDownward
import androidx.compose.material.icons.rounded.ArrowUpward
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.DeleteOutline
import androidx.compose.material.icons.rounded.KeyboardArrowDown
import androidx.compose.material.icons.rounded.KeyboardArrowUp
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.NetworkCheck
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Sync
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.R
import com.example.ui.theme.AmberConnecting
import com.example.ui.theme.CoralDisconnect
import com.example.ui.theme.CyanPulse
import com.example.ui.theme.DeepNavySurface
import com.example.ui.theme.ElevatedSlateCard
import com.example.ui.theme.EmeraldShield
import com.example.ui.theme.JetBrainsMonoFamily
import com.example.ui.theme.ObsidianBg
import com.example.ui.theme.SlateOutline
import com.example.ui.theme.SpaceGroteskFamily
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.example.ui.theme.VioletUdp
import com.example.vpn.model.SshTunnelMode
import com.example.vpn.model.TrafficStats
import com.example.vpn.model.VpnConnectionState
import com.example.vpn.model.VpnProtocol
import com.example.vpn.model.VpnServer
import com.example.vpn.parser.VpnLinkParser
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.delay

@Composable
fun MainScreen(
  uiState: MainUiState,
  onUpdateServers: () -> Unit,
  onSelectServer: (VpnServer) -> Unit,
  onPingSelected: () -> Unit,
  onConnectClick: () -> Unit,
  onDisconnectClick: () -> Unit,
  onOpenImportDialog: () -> Unit,
  onEditServer: (VpnServer) -> Unit,
  onCloseImportDialog: () -> Unit,
  onOpenExportDialog: (VpnServer) -> Unit,
  onCloseExportDialog: () -> Unit,
  onImportLink: (String) -> Unit,
  onAddSshServer: (
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
  ) -> Unit,
  onAddUdpServer: (
    name: String,
    host: String,
    portRange: String,
    password: String,
    receiveWindow: Int,
    editingServerId: String?,
  ) -> Unit,
  onDeleteCustomServer: (String) -> Unit,
  onShowMessage: (String) -> Unit,
  onDismissMessage: () -> Unit,
) {
  val context = LocalContext.current
  val snackbarHostState = remember { SnackbarHostState() }
  val runtime = uiState.runtimeState

  LaunchedEffect(uiState.statusBannerMessage) {
    val msg = uiState.statusBannerMessage
    if (!msg.isNullOrBlank()) {
      snackbarHostState.showSnackbar(msg)
      onDismissMessage()
    }
  }

  val accentColor by
    animateColorAsState(
      targetValue =
        when (runtime.connectionState) {
          VpnConnectionState.CONNECTED -> EmeraldShield
          VpnConnectionState.CONNECTING,
          VpnConnectionState.DISCONNECTING -> AmberConnecting
          VpnConnectionState.ERROR -> CoralDisconnect
          VpnConnectionState.DISCONNECTED -> CyanPulse
        },
      animationSpec = tween(450),
      label = "accentColor",
    )

  Scaffold(
    modifier = Modifier.fillMaxSize(),
    containerColor = ObsidianBg,
    contentWindowInsets = WindowInsets(0, 0, 0, 0),
    snackbarHost = {
      SnackbarHost(hostState = snackbarHostState, modifier = Modifier.navigationBarsPadding())
    },
  ) { innerPadding ->
    Box(
      modifier =
        Modifier.fillMaxSize()
          .padding(innerPadding)
          .background(
            Brush.verticalGradient(
              colors = listOf(ObsidianBg, Color(0xFF0A1120), ObsidianBg),
            )
          )
    ) {
      // Subtle atmospheric ambient glow behind center hero
      Canvas(modifier = Modifier.fillMaxSize()) {
        drawCircle(
          brush =
            Brush.radialGradient(
              colors =
                listOf(
                  accentColor.copy(
                    alpha =
                      if (runtime.connectionState == VpnConnectionState.CONNECTED) 0.16f else 0.08f
                  ),
                  Color.Transparent,
                ),
              center = Offset(size.width / 2f, size.height * 0.52f),
              radius = size.minDimension * 0.72f,
            ),
          center = Offset(size.width / 2f, size.height * 0.52f),
          radius = size.minDimension * 0.72f,
        )
      }

      Column(
        modifier =
          Modifier.fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .widthIn(max = 560.dp)
            .align(Alignment.Center)
            .padding(horizontal = 20.dp, vertical = 14.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
      ) {
        // 1. Top Bar with App Brand + 'Update Servers' button at top-right
        TopHeaderBar(
          isUpdating = uiState.isUpdatingServers,
          coreAvailable = runtime.coreAvailable,
          onUpdateServers = onUpdateServers,
        )

        Spacer(modifier = Modifier.height(18.dp))

        // 2. Server Selection Dropdown Card
        ServerSelectorDropdown(
          servers = uiState.servers,
          selectedServer = uiState.selectedServer,
          isPinging = uiState.isPinging,
          lastUpdatedMs = uiState.lastUpdatedMs,
          onSelectServer = onSelectServer,
          onPingSelected = onPingSelected,
          onOpenImportDialog = onOpenImportDialog,
          onEditServer = onEditServer,
          onOpenExportDialog = onOpenExportDialog,
          onCopyServer = { server ->
            if (!server.isLocked) {
              copyToClipboard(context, VpnLinkParser.toShareUri(server, locked = false))
              onShowMessage("Copied ${server.protocol.displayName} link for ${server.name}")
            }
          },
          onDeleteCustomServer = onDeleteCustomServer,
        )

        // Error or preview core info pill
        AnimatedVisibility(
          visible = !runtime.errorMessage.isNullOrBlank(),
          enter = fadeIn(),
          exit = fadeOut(),
        ) {
          ErrorInfoBanner(
            message = runtime.errorMessage.orEmpty(),
            onDismiss = onDismissMessage,
            modifier = Modifier.padding(top = 12.dp),
          )
        }

        // 3. Center Hero Circular Connect / Disconnect Button
        Box(
          modifier = Modifier.weight(1f).fillMaxWidth(),
          contentAlignment = Alignment.Center,
        ) {
          Column(horizontalAlignment = Alignment.CenterHorizontally) {
            CircularPowerButton(
              connectionState = runtime.connectionState,
              accentColor = accentColor,
              onClick = {
                when (runtime.connectionState) {
                  VpnConnectionState.CONNECTED,
                  VpnConnectionState.CONNECTING -> onDisconnectClick()
                  VpnConnectionState.DISCONNECTED,
                  VpnConnectionState.ERROR -> onConnectClick()
                  VpnConnectionState.DISCONNECTING -> Unit
                }
              },
            )

            Spacer(modifier = Modifier.height(22.dp))

            ConnectionStatusSummary(
              connectionState = runtime.connectionState,
              connectedAtElapsedMs = runtime.connectedAtElapsedMs,
              activeServerName = runtime.activeServerName ?: uiState.selectedServer?.name,
              accentColor = accentColor,
            )
          }
        }

        // 4. Bottom Live Telemetry Strip
        TelemetryBottomStrip(
          trafficStats = runtime.trafficStats,
          selectedServer = uiState.selectedServer,
          isConnected = runtime.connectionState == VpnConnectionState.CONNECTED,
        )

        Spacer(modifier = Modifier.height(6.dp))
      }
    }
  }

  if (uiState.showImportDialog) {
    AddServerDialog(
      editingServer = uiState.editingServer,
      onDismiss = onCloseImportDialog,
      onImportLink = onImportLink,
      onAddSshServer = onAddSshServer,
      onAddUdpServer = onAddUdpServer,
      onExportServer = { server -> onOpenExportDialog(server) },
    )
  }

  val exportingServer = uiState.exportingServer
  if (exportingServer != null && !exportingServer.isLocked) {
    ExportConfigDialog(
      server = exportingServer,
      onDismiss = onCloseExportDialog,
      onCopyUri = { uri, isLocked ->
        copyToClipboard(context, uri)
        val label = if (isLocked) "locked paolock://" else exportingServer.protocol.displayName
        onShowMessage("Copied $label link for ${exportingServer.name}")
      },
      onShareUri = { uri, title ->
        shareText(context, uri, title)
      },
      onShowMessage = onShowMessage,
    )
  }
}

@Composable
private fun TopHeaderBar(
  isUpdating: Boolean,
  coreAvailable: Boolean,
  onUpdateServers: () -> Unit,
) {
  val infiniteTransition = rememberInfiniteTransition(label = "syncSpin")
  val rotation by
    infiniteTransition.animateFloat(
      initialValue = 0f,
      targetValue = 360f,
      animationSpec = infiniteRepeatable(tween(900, easing = LinearEasing)),
      label = "syncAngle",
    )

  Row(
    modifier = Modifier.fillMaxWidth(),
    horizontalArrangement = Arrangement.SpaceBetween,
    verticalAlignment = Alignment.CenterVertically,
  ) {
    Row(verticalAlignment = Alignment.CenterVertically) {
      Box(
        modifier =
          Modifier.size(40.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(ElevatedSlateCard)
            .border(1.dp, SlateOutline, RoundedCornerShape(12.dp)),
        contentAlignment = Alignment.Center,
      ) {
        Icon(
          imageVector = Icons.Rounded.Shield,
          contentDescription = stringResource(R.string.app_name),
          tint = EmeraldShield,
          modifier = Modifier.size(22.dp),
        )
      }
      Spacer(modifier = Modifier.width(12.dp))
      Column {
        Text(
          text = stringResource(R.string.app_name),
          style = MaterialTheme.typography.titleLarge,
          color = TextPrimary,
        )
        Text(
          text = if (coreAvailable) "Xray · SSH · UDP Ready" else "SSH · UDP Ready",
          style = MaterialTheme.typography.labelSmall,
          color = if (coreAvailable) EmeraldShield else TextMuted,
        )
      }
    }

    Button(
      onClick = onUpdateServers,
      enabled = !isUpdating,
      shape = RoundedCornerShape(50),
      colors =
        ButtonDefaults.buttonColors(
          containerColor = ElevatedSlateCard,
          contentColor = CyanPulse,
          disabledContainerColor = ElevatedSlateCard.copy(alpha = 0.7f),
          disabledContentColor = CyanPulse.copy(alpha = 0.7f),
        ),
      border = BorderStroke(1.dp, CyanPulse.copy(alpha = 0.35f)),
      contentPadding = PaddingValues(horizontal = 14.dp, vertical = 10.dp),
      modifier = Modifier.minimumInteractiveComponentSize().testTag("update_servers_button"),
    ) {
      Icon(
        imageVector = Icons.Rounded.Sync,
        contentDescription = stringResource(R.string.update_servers),
        modifier = Modifier.size(18.dp).rotate(if (isUpdating) rotation else 0f),
      )
      Spacer(modifier = Modifier.width(6.dp))
      Text(
        text =
          if (isUpdating) {
            stringResource(R.string.updating_servers)
          } else {
            stringResource(R.string.update_servers)
          },
        style = MaterialTheme.typography.labelLarge.copy(fontSize = 13.sp),
      )
    }
  }
}

@Composable
private fun ServerSelectorDropdown(
  servers: List<VpnServer>,
  selectedServer: VpnServer?,
  isPinging: Boolean,
  lastUpdatedMs: Long?,
  onSelectServer: (VpnServer) -> Unit,
  onPingSelected: () -> Unit,
  onOpenImportDialog: () -> Unit,
  onEditServer: (VpnServer) -> Unit,
  onOpenExportDialog: (VpnServer) -> Unit,
  onCopyServer: (VpnServer) -> Unit,
  onDeleteCustomServer: (String) -> Unit,
) {
  var expanded by remember { mutableStateOf(false) }

  Column(modifier = Modifier.fillMaxWidth()) {
    Row(
      modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 4.dp),
      horizontalArrangement = Arrangement.SpaceBetween,
      verticalAlignment = Alignment.CenterVertically,
    ) {
      Text(
        text = "SERVER NODE (${servers.size})",
        style = MaterialTheme.typography.labelSmall,
        color = TextMuted,
      )
      if (lastUpdatedMs != null) {
        val formatted = remember(lastUpdatedMs) {
          SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()).format(Date(lastUpdatedMs))
        }
        Text(
          text = "Synced $formatted",
          style = MaterialTheme.typography.labelSmall,
          color = TextMuted,
        )
      }
    }

    Spacer(modifier = Modifier.height(4.dp))

    BoxWithConstraints(modifier = Modifier.fillMaxWidth()) {
      val dropdownWidth = maxWidth
      Surface(
        shape = RoundedCornerShape(18.dp),
        color = DeepNavySurface,
        border = BorderStroke(1.dp, SlateOutline),
        modifier =
          Modifier.fillMaxWidth()
            .clip(RoundedCornerShape(18.dp))
            .clickable { expanded = true }
            .testTag("server_dropdown_button"),
      ) {
        Row(
          modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 14.dp),
          verticalAlignment = Alignment.CenterVertically,
        ) {
          if (selectedServer != null) {
            ProtocolBadge(protocol = selectedServer.protocol)
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
              Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                  text = selectedServer.name,
                  style = MaterialTheme.typography.titleMedium,
                  color = TextPrimary,
                  maxLines = 1,
                  overflow = TextOverflow.Ellipsis,
                  modifier = Modifier.weight(1f, fill = false),
                )
                if (selectedServer.isLocked) {
                  Spacer(modifier = Modifier.width(6.dp))
                  Icon(
                    imageVector = Icons.Rounded.Lock,
                    contentDescription = "Locked config",
                    tint = AmberConnecting,
                    modifier = Modifier.size(15.dp).testTag("selected_locked_icon"),
                  )
                }
              }
              Spacer(modifier = Modifier.height(2.dp))
              Text(
                text = selectedServer.homeDisplaySubtitle,
                style = MaterialTheme.typography.labelSmall,
                color = TextSecondary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.testTag("selected_server_subtitle"),
              )
            }
            if (selectedServer.latencyMs != null) {
              LatencyPill(latencyMs = selectedServer.latencyMs)
              Spacer(modifier = Modifier.width(4.dp))
            }
            IconButton(
              onClick = onPingSelected,
              enabled = !isPinging,
              modifier = Modifier.size(40.dp).testTag("ping_server_button"),
            ) {
              Icon(
                imageVector = Icons.Rounded.NetworkCheck,
                contentDescription = stringResource(R.string.test_ping),
                tint = if (isPinging) AmberConnecting else CyanPulse,
                modifier = Modifier.size(20.dp),
              )
            }
            if (!selectedServer.isLocked) {
              IconButton(
                onClick = { onOpenExportDialog(selectedServer) },
                modifier = Modifier.size(40.dp).testTag("selected_share_button"),
              ) {
                Icon(
                  imageVector = Icons.Rounded.Share,
                  contentDescription = "Share or export config",
                  tint = EmeraldShield,
                  modifier = Modifier.size(19.dp),
                )
              }
            }
          } else {
            Icon(
              imageVector = Icons.Rounded.Public,
              contentDescription = null,
              tint = CyanPulse,
              modifier = Modifier.size(22.dp),
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
              Text(
                text = stringResource(R.string.no_servers_title),
                style = MaterialTheme.typography.titleMedium,
                color = TextPrimary,
              )
              Text(
                text = stringResource(R.string.no_servers_hint),
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
              )
            }
          }

          Icon(
            imageVector =
              if (expanded) Icons.Rounded.KeyboardArrowUp else Icons.Rounded.KeyboardArrowDown,
            contentDescription = stringResource(R.string.select_server),
            tint = TextSecondary,
            modifier = Modifier.size(24.dp),
          )
        }
      }

      DropdownMenu(
        expanded = expanded,
        onDismissRequest = { expanded = false },
        modifier =
          Modifier.width(dropdownWidth)
            .heightIn(max = 360.dp)
            .background(ElevatedSlateCard)
            .border(1.dp, SlateOutline, RoundedCornerShape(12.dp))
            .testTag("server_dropdown_menu"),
      ) {
        if (servers.isEmpty()) {
          DropdownMenuItem(
            text = {
              Text(
                text = "No servers yet — tap Update Servers or Import Link",
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary,
              )
            },
            onClick = { expanded = false },
          )
        } else {
          servers.forEach { server ->
            val isSelected = server.id == selectedServer?.id
            DropdownMenuItem(
              text = {
                Row(
                  modifier = Modifier.fillMaxWidth(),
                  verticalAlignment = Alignment.CenterVertically,
                ) {
                  ProtocolBadge(protocol = server.protocol)
                  Spacer(modifier = Modifier.width(10.dp))
                  Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                      Text(
                        text = server.name,
                        style = MaterialTheme.typography.bodyLarge,
                        color = if (isSelected) EmeraldShield else TextPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false),
                      )
                      if (server.isLocked) {
                        Spacer(modifier = Modifier.width(5.dp))
                        Icon(
                          imageVector = Icons.Rounded.Lock,
                          contentDescription = "Locked config",
                          tint = AmberConnecting,
                          modifier = Modifier.size(14.dp),
                        )
                      }
                    }
                    Text(
                      text = server.homeDisplaySubtitle,
                      style = MaterialTheme.typography.labelSmall,
                      color = TextMuted,
                      maxLines = 1,
                      overflow = TextOverflow.Ellipsis,
                    )
                  }
                  if (server.latencyMs != null) {
                    LatencyPill(latencyMs = server.latencyMs)
                    Spacer(modifier = Modifier.width(6.dp))
                  }
                  if (isSelected) {
                    Icon(
                      imageVector = Icons.Rounded.CheckCircle,
                      contentDescription = "Selected",
                      tint = EmeraldShield,
                      modifier = Modifier.size(18.dp),
                    )
                  }
                  if (!server.isLocked) {
                    IconButton(
                      onClick = {
                        expanded = false
                        onOpenExportDialog(server)
                      },
                      modifier = Modifier.size(36.dp).testTag("dropdown_share_button"),
                    ) {
                      Icon(
                        imageVector = Icons.Rounded.Share,
                        contentDescription = "Share or export config",
                        tint = EmeraldShield,
                        modifier = Modifier.size(17.dp),
                      )
                    }
                    IconButton(
                      onClick = {
                        expanded = false
                        onCopyServer(server)
                      },
                      modifier = Modifier.size(36.dp).testTag("dropdown_copy_button"),
                    ) {
                      Icon(
                        imageVector = Icons.Rounded.ContentCopy,
                        contentDescription = "Copy config link",
                        tint = CyanPulse,
                        modifier = Modifier.size(17.dp),
                      )
                    }
                    if (server.protocol == VpnProtocol.SSH || server.protocol == VpnProtocol.UDP) {
                      IconButton(
                        onClick = {
                          expanded = false
                          onEditServer(server)
                        },
                        modifier = Modifier.size(36.dp).testTag("dropdown_edit_server_button"),
                      ) {
                        Icon(
                          imageVector = Icons.Rounded.Tune,
                          contentDescription = "Edit config",
                          tint = AmberConnecting,
                          modifier = Modifier.size(17.dp),
                        )
                      }
                    }
                  }
                  if (server.isCustom) {
                    IconButton(
                      onClick = { onDeleteCustomServer(server.id) },
                      modifier = Modifier.size(36.dp),
                    ) {
                      Icon(
                        imageVector = Icons.Rounded.DeleteOutline,
                        contentDescription = "Delete custom server",
                        tint = CoralDisconnect,
                        modifier = Modifier.size(18.dp),
                      )
                    }
                  }
                }
              },
              onClick = {
                expanded = false
                onSelectServer(server)
              },
            )
          }
        }

        HorizontalDivider(color = SlateOutline)

        DropdownMenuItem(
          leadingIcon = {
            Icon(
              imageVector = Icons.Rounded.AddLink,
              contentDescription = null,
              tint = CyanPulse,
            )
          },
          text = {
            Text(
              text = stringResource(R.string.import_link),
              style = MaterialTheme.typography.titleMedium.copy(fontSize = 14.sp),
              color = CyanPulse,
            )
          },
          onClick = {
            expanded = false
            onOpenImportDialog()
          },
          modifier = Modifier.testTag("import_link_menu_item"),
        )
      }
    }
  }
}

@Composable
private fun ProtocolBadge(protocol: VpnProtocol) {
  val fg =
    when (protocol) {
      VpnProtocol.VLESS -> CyanPulse
      VpnProtocol.VMESS -> EmeraldShield
      VpnProtocol.SSH -> AmberConnecting
      VpnProtocol.UDP -> VioletUdp
    }
  val bg = fg.copy(alpha = 0.16f)
  Box(
    modifier =
      Modifier.clip(RoundedCornerShape(8.dp))
        .background(bg)
        .border(1.dp, fg.copy(alpha = 0.35f), RoundedCornerShape(8.dp))
        .padding(horizontal = 8.dp, vertical = 4.dp)
  ) {
    Text(
      text = protocol.displayName.uppercase(),
      style = MaterialTheme.typography.labelSmall,
      color = fg,
    )
  }
}

@Composable
private fun LatencyPill(latencyMs: Long) {
  val color =
    when {
      latencyMs < 120 -> EmeraldShield
      latencyMs < 260 -> AmberConnecting
      else -> CoralDisconnect
    }
  Box(
    modifier =
      Modifier.clip(RoundedCornerShape(50))
        .background(color.copy(alpha = 0.14f))
        .padding(horizontal = 7.dp, vertical = 3.dp)
  ) {
    Text(
      text = "${latencyMs}ms",
      style = MaterialTheme.typography.labelSmall,
      color = color,
    )
  }
}

@Composable
private fun CircularPowerButton(
  connectionState: VpnConnectionState,
  accentColor: Color,
  onClick: () -> Unit,
) {
  val isConnecting = connectionState == VpnConnectionState.CONNECTING
  val isConnected = connectionState == VpnConnectionState.CONNECTED

  val infiniteTransition = rememberInfiniteTransition(label = "radarPulse")
  val pulse1 by
    infiniteTransition.animateFloat(
      initialValue = 0f,
      targetValue = 1f,
      animationSpec = infiniteRepeatable(tween(2200, easing = FastOutSlowInEasing)),
      label = "pulse1",
    )
  val pulse2 by
    infiniteTransition.animateFloat(
      initialValue = 0f,
      targetValue = 1f,
      animationSpec =
        infiniteRepeatable(
          animation = tween(2200, delayMillis = 900, easing = FastOutSlowInEasing),
          repeatMode = RepeatMode.Restart,
        ),
      label = "pulse2",
    )

  val buttonScale by
    animateFloatAsState(
      targetValue = if (isConnected) 1.03f else 1f,
      animationSpec = spring(dampingRatio = 0.6f, stiffness = 260f),
      label = "buttonScale",
    )

  val buttonLabel =
    when (connectionState) {
      VpnConnectionState.DISCONNECTED,
      VpnConnectionState.ERROR -> stringResource(R.string.connect)
      VpnConnectionState.CONNECTING -> stringResource(R.string.connecting)
      VpnConnectionState.CONNECTED -> stringResource(R.string.disconnect)
      VpnConnectionState.DISCONNECTING -> stringResource(R.string.disconnecting)
    }

  Box(modifier = Modifier.size(276.dp), contentAlignment = Alignment.Center) {
    // Animated sonar rings
    Canvas(modifier = Modifier.fillMaxSize()) {
      val baseRadius = 104.dp.toPx()
      val maxExtra = 34.dp.toPx()

      if (isConnected || isConnecting) {
        listOf(pulse1, pulse2).forEach { progress ->
          val r = baseRadius + maxExtra * progress
          val alpha = (1f - progress) * if (isConnecting) 0.45f else 0.28f
          drawCircle(
            color = accentColor.copy(alpha = alpha),
            radius = r,
            style = Stroke(width = 2.dp.toPx()),
          )
        }
      } else {
        drawCircle(
          color = SlateOutline.copy(alpha = 0.55f),
          radius = baseRadius + 14.dp.toPx(),
          style = Stroke(width = 1.5.dp.toPx()),
        )
      }
    }

    // Main big circular Connect/Disconnect button
    Surface(
      shape = CircleShape,
      color = DeepNavySurface,
      shadowElevation = if (isConnected) 22.dp else 10.dp,
      modifier =
        Modifier.size(204.dp)
          .scale(buttonScale)
          .clip(CircleShape)
          .border(
            width = 3.dp,
            brush =
              Brush.linearGradient(
                colors =
                  listOf(
                    accentColor,
                    accentColor.copy(alpha = 0.35f),
                    accentColor,
                  )
              ),
            shape = CircleShape,
          )
          .clickable(
            enabled = connectionState != VpnConnectionState.DISCONNECTING,
            onClick = onClick,
          )
          .testTag("connect_button"),
    ) {
      Box(
        modifier =
          Modifier.fillMaxSize()
            .background(
              Brush.radialGradient(
                colors =
                  listOf(
                    accentColor.copy(alpha = if (isConnected) 0.22f else 0.10f),
                    DeepNavySurface,
                  )
              )
            ),
        contentAlignment = Alignment.Center,
      ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
          Icon(
            imageVector = Icons.Rounded.PowerSettingsNew,
            contentDescription = buttonLabel,
            tint = accentColor,
            modifier = Modifier.size(56.dp),
          )
          Spacer(modifier = Modifier.height(10.dp))
          Text(
            text = buttonLabel,
            fontFamily = SpaceGroteskFamily,
            fontWeight = FontWeight.Bold,
            fontSize = 16.sp,
            letterSpacing = 1.6.sp,
            color = TextPrimary,
          )
        }
      }
    }
  }
}

@Composable
private fun ConnectionStatusSummary(
  connectionState: VpnConnectionState,
  connectedAtElapsedMs: Long?,
  activeServerName: String?,
  accentColor: Color,
) {
  var elapsedSeconds by remember(connectedAtElapsedMs, connectionState) { mutableLongStateOf(0L) }

  LaunchedEffect(connectedAtElapsedMs, connectionState) {
    if (connectionState == VpnConnectionState.CONNECTED && connectedAtElapsedMs != null) {
      while (true) {
        elapsedSeconds = ((SystemClock.elapsedRealtime() - connectedAtElapsedMs) / 1000L).coerceAtLeast(0L)
        delay(1000L)
      }
    } else {
      elapsedSeconds = 0L
    }
  }

  val statusText =
    when (connectionState) {
      VpnConnectionState.CONNECTED -> stringResource(R.string.status_connected)
      VpnConnectionState.CONNECTING -> stringResource(R.string.status_connecting)
      VpnConnectionState.DISCONNECTING -> stringResource(R.string.status_disconnecting)
      VpnConnectionState.DISCONNECTED -> stringResource(R.string.status_disconnected)
      VpnConnectionState.ERROR -> "Connection Failed"
    }

  Column(horizontalAlignment = Alignment.CenterHorizontally) {
    Row(
      verticalAlignment = Alignment.CenterVertically,
      modifier =
        Modifier.clip(RoundedCornerShape(50))
          .background(accentColor.copy(alpha = 0.12f))
          .border(1.dp, accentColor.copy(alpha = 0.3f), RoundedCornerShape(50))
          .padding(horizontal = 14.dp, vertical = 6.dp),
    ) {
      Box(modifier = Modifier.size(8.dp).clip(CircleShape).background(accentColor))
      Spacer(modifier = Modifier.width(8.dp))
      Text(
        text = statusText,
        style = MaterialTheme.typography.labelLarge.copy(fontSize = 13.sp),
        color = accentColor,
      )
    }

    Spacer(modifier = Modifier.height(10.dp))

    if (connectionState == VpnConnectionState.CONNECTED) {
      Text(
        text = formatDuration(elapsedSeconds),
        fontFamily = JetBrainsMonoFamily,
        fontWeight = FontWeight.SemiBold,
        fontSize = 26.sp,
        color = TextPrimary,
      )
      if (!activeServerName.isNullOrBlank()) {
        Spacer(modifier = Modifier.height(2.dp))
        Text(
          text = activeServerName,
          style = MaterialTheme.typography.bodyMedium,
          color = TextSecondary,
          maxLines = 1,
          overflow = TextOverflow.Ellipsis,
        )
      }
    } else {
      Text(
        text =
          if (!activeServerName.isNullOrBlank()) {
            "Ready · $activeServerName"
          } else {
            "Select a server to begin"
          },
        style = MaterialTheme.typography.bodyMedium,
        color = TextSecondary,
        textAlign = TextAlign.Center,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
      )
    }
  }
}

@Composable
private fun TelemetryBottomStrip(
  trafficStats: TrafficStats,
  selectedServer: VpnServer?,
  isConnected: Boolean,
) {
  Row(
    modifier = Modifier.fillMaxWidth(),
    horizontalArrangement = Arrangement.spacedBy(10.dp),
  ) {
    TelemetryCard(
      label = stringResource(R.string.upload_label),
      value = if (isConnected) formatSpeed(trafficStats.uplinkSpeedBps) else "0 B/s",
      subValue = if (isConnected) formatBytes(trafficStats.uplinkBytes) else "Total 0 B",
      icon = Icons.Rounded.ArrowUpward,
      tint = CyanPulse,
      modifier = Modifier.weight(1f),
    )
    TelemetryCard(
      label = stringResource(R.string.download_label),
      value = if (isConnected) formatSpeed(trafficStats.downlinkSpeedBps) else "0 B/s",
      subValue = if (isConnected) formatBytes(trafficStats.downlinkBytes) else "Total 0 B",
      icon = Icons.Rounded.ArrowDownward,
      tint = EmeraldShield,
      modifier = Modifier.weight(1f),
    )
    TelemetryCard(
      label = stringResource(R.string.latency_label),
      value = selectedServer?.latencyMs?.let { "$it ms" } ?: "—",
      subValue =
        when {
          selectedServer == null -> "Xray"
          selectedServer.isSlowDns -> "SlowDNS"
          else -> selectedServer.protocol.displayName
        },
      icon = Icons.Rounded.NetworkCheck,
      tint = AmberConnecting,
      modifier = Modifier.weight(1f),
    )
  }
}

@Composable
private fun TelemetryCard(
  label: String,
  value: String,
  subValue: String,
  icon: androidx.compose.ui.graphics.vector.ImageVector,
  tint: Color,
  modifier: Modifier = Modifier,
) {
  Surface(
    shape = RoundedCornerShape(16.dp),
    color = DeepNavySurface,
    border = BorderStroke(1.dp, SlateOutline),
    modifier = modifier,
  ) {
    Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 12.dp)) {
      Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
          imageVector = icon,
          contentDescription = label,
          tint = tint,
          modifier = Modifier.size(14.dp),
        )
        Spacer(modifier = Modifier.width(4.dp))
        Text(
          text = label,
          style = MaterialTheme.typography.labelSmall,
          color = TextMuted,
          maxLines = 1,
        )
      }
      Spacer(modifier = Modifier.height(6.dp))
      Text(
        text = value,
        style = MaterialTheme.typography.labelMedium.copy(fontSize = 13.sp, fontWeight = FontWeight.Bold),
        color = TextPrimary,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
      )
      Spacer(modifier = Modifier.height(2.dp))
      Text(
        text = subValue,
        style = MaterialTheme.typography.labelSmall,
        color = TextSecondary,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
      )
    }
  }
}

@Composable
private fun ErrorInfoBanner(
  message: String,
  onDismiss: () -> Unit,
  modifier: Modifier = Modifier,
) {
  Surface(
    shape = RoundedCornerShape(14.dp),
    color = CoralDisconnect.copy(alpha = 0.12f),
    border = BorderStroke(1.dp, CoralDisconnect.copy(alpha = 0.4f)),
    modifier = modifier.fillMaxWidth().clickable(onClick = onDismiss),
  ) {
    Row(
      modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
      verticalAlignment = Alignment.CenterVertically,
    ) {
      Icon(
        imageVector = Icons.Rounded.WarningAmber,
        contentDescription = null,
        tint = CoralDisconnect,
        modifier = Modifier.size(18.dp),
      )
      Spacer(modifier = Modifier.width(10.dp))
      Text(
        text = message,
        style = MaterialTheme.typography.bodyMedium,
        color = TextPrimary,
        modifier = Modifier.weight(1f),
      )
    }
  }
}

private fun copyToClipboard(context: Context, text: String) {
  val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
  clipboard?.setPrimaryClip(ClipData.newPlainText("PAO Tunnel Link", text))
}

private fun shareText(context: Context, text: String, title: String) {
  val intent =
    Intent(Intent.ACTION_SEND).apply {
      type = "text/plain"
      putExtra(Intent.EXTRA_SUBJECT, title)
      putExtra(Intent.EXTRA_TEXT, text)
    }
  context.startActivity(Intent.createChooser(intent, "Share Config Link"))
}

private fun formatDuration(totalSeconds: Long): String {
  val hours = totalSeconds / 3600
  val minutes = (totalSeconds % 3600) / 60
  val seconds = totalSeconds % 60
  return String.format(Locale.US, "%02d:%02d:%02d", hours, minutes, seconds)
}

private fun formatBytes(bytes: Long): String {
  if (bytes < 1024) return "$bytes B"
  val kb = bytes / 1024.0
  if (kb < 1024) return String.format(Locale.US, "%.1f KB", kb)
  val mb = kb / 1024.0
  if (mb < 1024) return String.format(Locale.US, "%.1f MB", mb)
  val gb = mb / 1024.0
  return String.format(Locale.US, "%.2f GB", gb)
}

private fun formatSpeed(bytesPerSec: Long): String = "${formatBytes(bytesPerSec)}/s"
