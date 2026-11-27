package com.example.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.FolderOpen
import androidx.compose.material.icons.rounded.Remove
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.R
import com.example.ui.theme.AmberConnecting
import com.example.ui.theme.CyanPulse
import com.example.ui.theme.DeepNavySurface
import com.example.ui.theme.ElevatedSlateCard
import com.example.ui.theme.EmeraldShield
import com.example.ui.theme.JetBrainsMonoFamily
import com.example.ui.theme.ObsidianBg
import com.example.ui.theme.SlateOutline
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.example.vpn.model.SshTunnelMode
import com.example.vpn.model.VpnProtocol
import com.example.vpn.model.VpnServer
import com.example.vpn.parser.VpnLinkParser
import java.nio.charset.StandardCharsets
import java.util.Locale

private enum class AddServerTab {
  V2RAY_LINK,
  SSH_FORM,
  UDP_ZIVPN,
}

@Composable
fun AddServerDialog(
  editingServer: VpnServer? = null,
  onDismiss: () -> Unit,
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
  onExportServer: (VpnServer) -> Unit = {},
) {
  val context = LocalContext.current
  val safeEditingServer = editingServer?.takeUnless { it.isLocked }
  val isEditingSsh = safeEditingServer?.protocol == VpnProtocol.SSH
  val isEditingUdp = safeEditingServer?.protocol == VpnProtocol.UDP
  var activeTab by
    remember(safeEditingServer?.id) {
      mutableStateOf(
        when {
          isEditingSsh -> AddServerTab.SSH_FORM
          isEditingUdp -> AddServerTab.UDP_ZIVPN
          else -> AddServerTab.V2RAY_LINK
        }
      )
    }
  var linkInput by remember { mutableStateOf("") }

  val openFileLauncher =
    rememberLauncherForActivityResult(
      contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
      if (uri != null) {
        val text =
          runCatching {
              context.contentResolver.openInputStream(uri)?.use { stream ->
                stream.readBytes().toString(StandardCharsets.UTF_8)
              }
            }
            .getOrNull()
        if (!text.isNullOrBlank()) {
          onImportLink(text)
        }
      }
    }

  var sshTunnelMode by
    remember(safeEditingServer?.id) {
      mutableStateOf(safeEditingServer?.sshTunnelMode ?: SshTunnelMode.DIRECT_PAYLOAD)
    }
  var sshName by remember(safeEditingServer?.id) { mutableStateOf(if (isEditingSsh) safeEditingServer?.name.orEmpty() else "") }
  var sshHost by remember(safeEditingServer?.id) { mutableStateOf(if (isEditingSsh) safeEditingServer?.address.orEmpty() else "") }
  var sshPortText by
    remember(safeEditingServer?.id) {
      mutableStateOf(
        if (isEditingSsh && safeEditingServer != null && safeEditingServer.port > 0) safeEditingServer.port.toString() else "22"
      )
    }
  var sshUsername by
    remember(safeEditingServer?.id) { mutableStateOf(if (isEditingSsh) safeEditingServer?.username.orEmpty() else "") }
  var sshPassword by
    remember(safeEditingServer?.id) { mutableStateOf(if (isEditingSsh) safeEditingServer?.password.orEmpty() else "") }
  var passwordVisible by remember { mutableStateOf(false) }
  var sshHttpProxy by
    remember(safeEditingServer?.id) { mutableStateOf(if (isEditingSsh) safeEditingServer?.sshProxyDisplay.orEmpty() else "") }
  var sshPayload by
    remember(safeEditingServer?.id) { mutableStateOf(if (isEditingSsh) safeEditingServer?.payload.orEmpty() else "") }
  var slowDnsServerIp by
    remember(safeEditingServer?.id) {
      mutableStateOf(if (isEditingSsh) safeEditingServer?.slowDnsServerIp?.ifBlank { "8.8.8.8" } ?: "8.8.8.8" else "8.8.8.8")
    }
  var slowDnsNameserver by
    remember(safeEditingServer?.id) { mutableStateOf(if (isEditingSsh) safeEditingServer?.slowDnsNameserver.orEmpty() else "") }
  var slowDnsPublicKey by
    remember(safeEditingServer?.id) { mutableStateOf(if (isEditingSsh) safeEditingServer?.slowDnsPublicKey.orEmpty() else "") }

  // ZIVPN UDP state
  var udpName by
    remember(safeEditingServer?.id) { mutableStateOf(if (isEditingUdp) safeEditingServer?.name.orEmpty() else "") }
  var udpHost by
    remember(safeEditingServer?.id) { mutableStateOf(if (isEditingUdp) safeEditingServer?.address.orEmpty() else "") }
  var udpPortRange by
    remember(safeEditingServer?.id) {
      mutableStateOf(if (isEditingUdp) safeEditingServer?.effectiveUdpPortRange ?: "6000-19999" else "6000-19999")
    }
  var udpPassword by
    remember(safeEditingServer?.id) { mutableStateOf(if (isEditingUdp) safeEditingServer?.password.orEmpty() else "") }
  var udpPasswordVisible by remember { mutableStateOf(false) }
  var udpReceiveWindow by
    remember(safeEditingServer?.id) {
      mutableIntStateOf(
        if (isEditingUdp) (safeEditingServer?.udpReceiveWindow ?: 2).coerceIn(1, 64) else 2
      )
    }

  val isSlowDns = sshTunnelMode == SshTunnelMode.SLOW_DNS
  val parsedSshPort = sshPortText.trim().toIntOrNull()
  val cleanPubkey = slowDnsPublicKey.trim()
  val isPubkeyValid =
    cleanPubkey.length == 64 && cleanPubkey.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
  val isSshValid =
    if (isSlowDns) {
      parsedSshPort != null &&
        parsedSshPort in 1..65535 &&
        sshUsername.isNotBlank() &&
        slowDnsServerIp.isNotBlank() &&
        VpnLinkParser.sanitizeSlowDnsNameserver(slowDnsNameserver).isNotBlank() &&
        isPubkeyValid
    } else {
      sshHost.isNotBlank() &&
        parsedSshPort != null &&
        parsedSshPort in 1..65535 &&
        sshUsername.isNotBlank()
    }

  val parsedUdpRange = VpnLinkParser.sanitizeUdpPortRange(udpPortRange)
  val isUdpValid =
    udpHost.isNotBlank() &&
      udpPassword.isNotEmpty() &&
      parsedUdpRange != null &&
      udpReceiveWindow in 1..64

  val fieldColors =
    OutlinedTextFieldDefaults.colors(
      focusedBorderColor = CyanPulse,
      unfocusedBorderColor = SlateOutline,
      focusedTextColor = TextPrimary,
      unfocusedTextColor = TextPrimary,
      focusedLabelColor = CyanPulse,
      unfocusedLabelColor = TextSecondary,
      cursorColor = CyanPulse,
    )

  AlertDialog(
    onDismissRequest = onDismiss,
    containerColor = ElevatedSlateCard,
    titleContentColor = TextPrimary,
    textContentColor = TextSecondary,
    title = {
      Text(
        text =
          when {
            isEditingSsh -> "SSH Server Config"
            isEditingUdp -> "UDP (ZIVPN) Config"
            else -> stringResource(R.string.import_link)
          },
        style = MaterialTheme.typography.titleLarge,
      )
    },
    text = {
      Column(modifier = Modifier.fillMaxWidth()) {
        // Protocol switcher
        Row(
          modifier =
            Modifier.fillMaxWidth()
              .clip(RoundedCornerShape(14.dp))
              .background(DeepNavySurface)
              .border(1.dp, SlateOutline, RoundedCornerShape(14.dp))
              .padding(4.dp),
          horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
          ProtocolTabButton(
            label = "Link / File",
            selected = activeTab == AddServerTab.V2RAY_LINK,
            accentColor = CyanPulse,
            onClick = { activeTab = AddServerTab.V2RAY_LINK },
            modifier = Modifier.weight(1f).testTag("protocol_tab_v2ray"),
          )
          ProtocolTabButton(
            label = "SSH Tunnel",
            selected = activeTab == AddServerTab.SSH_FORM,
            accentColor = AmberConnecting,
            onClick = { activeTab = AddServerTab.SSH_FORM },
            modifier = Modifier.weight(1f).testTag("protocol_tab_ssh"),
          )
          ProtocolTabButton(
            label = "UDP (ZIVPN)",
            selected = activeTab == AddServerTab.UDP_ZIVPN,
            accentColor = EmeraldShield,
            onClick = { activeTab = AddServerTab.UDP_ZIVPN },
            modifier = Modifier.weight(1f).testTag("protocol_tab_udp"),
          )
        }

        Spacer(modifier = Modifier.height(14.dp))

        when (activeTab) {
          AddServerTab.V2RAY_LINK -> {
            Text(
              text = "Paste a vless://, vmess://, ssh://, udp://, or locked paolock:// link, or import a .pao config file.",
              style = MaterialTheme.typography.bodyMedium,
              color = TextSecondary,
            )
            Spacer(modifier = Modifier.height(12.dp))
            OutlinedTextField(
              value = linkInput,
              onValueChange = { linkInput = it },
              placeholder = {
                Text(
                  text = "vless://, vmess://, ssh://, udp://, or paolock://...",
                  style = MaterialTheme.typography.bodyMedium,
                  color = TextMuted,
                )
              },
              minLines = 3,
              maxLines = 5,
              colors = fieldColors,
              modifier = Modifier.fillMaxWidth().testTag("import_link_input"),
            )
            Spacer(modifier = Modifier.height(10.dp))
            OutlinedButton(
              onClick = { openFileLauncher.launch(arrayOf("*/*")) },
              border = BorderStroke(1.dp, CyanPulse.copy(alpha = 0.45f)),
              colors = ButtonDefaults.outlinedButtonColors(contentColor = CyanPulse),
              modifier = Modifier.fillMaxWidth().testTag("import_config_file_button"),
            ) {
              Icon(
                imageVector = Icons.Rounded.FolderOpen,
                contentDescription = "Import Config File",
                modifier = Modifier.size(18.dp),
              )
              Spacer(modifier = Modifier.width(8.dp))
              Text("Import Config File (.pao / .txt)", style = MaterialTheme.typography.labelLarge)
            }
          }

          AddServerTab.SSH_FORM -> {
            Column(
              modifier =
                Modifier.fillMaxWidth()
                  .heightIn(max = 420.dp)
                  .verticalScroll(rememberScrollState()),
              verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
              Text(
                text = "Connection Mode",
                style = MaterialTheme.typography.labelSmall,
                color = TextSecondary,
              )
              Row(
                modifier =
                  Modifier.fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(DeepNavySurface)
                    .border(1.dp, SlateOutline, RoundedCornerShape(12.dp))
                    .padding(4.dp),
                horizontalArrangement = Arrangement.spacedBy(4.dp),
              ) {
                ProtocolTabButton(
                  label = "Direct / Payload",
                  selected = sshTunnelMode == SshTunnelMode.DIRECT_PAYLOAD,
                  accentColor = AmberConnecting,
                  onClick = { sshTunnelMode = SshTunnelMode.DIRECT_PAYLOAD },
                  modifier = Modifier.weight(1f).testTag("ssh_mode_direct"),
                )
                ProtocolTabButton(
                  label = "SlowDNS (DNSTT)",
                  selected = sshTunnelMode == SshTunnelMode.SLOW_DNS,
                  accentColor = EmeraldShield,
                  onClick = { sshTunnelMode = SshTunnelMode.SLOW_DNS },
                  modifier = Modifier.weight(1f).testTag("ssh_mode_slowdns"),
                )
              }

              OutlinedTextField(
                value = sshName,
                onValueChange = { sshName = it },
                label = { Text("Server Name (Optional)") },
                placeholder = {
                  Text(if (isSlowDns) "SlowDNS Node" else "SG SSH Node", color = TextMuted)
                },
                singleLine = true,
                colors = fieldColors,
                modifier = Modifier.fillMaxWidth().testTag("ssh_name_input"),
              )

              Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
              ) {
                OutlinedTextField(
                  value = sshHost,
                  onValueChange = { sshHost = it },
                  label = { Text(if (isSlowDns) "SSH Host (Optional)" else "Host / IP") },
                  placeholder = {
                    Text(if (isSlowDns) "127.0.0.1" else "157.85.103.29", color = TextMuted)
                  },
                  singleLine = true,
                  colors = fieldColors,
                  modifier = Modifier.weight(0.65f).testTag("ssh_host_input"),
                )
                OutlinedTextField(
                  value = sshPortText,
                  onValueChange = { input ->
                    sshPortText = input.filter { it.isDigit() }.take(5)
                  },
                  label = { Text("Port") },
                  placeholder = { Text("22", color = TextMuted) },
                  singleLine = true,
                  keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                  colors = fieldColors,
                  modifier = Modifier.weight(0.35f).testTag("ssh_port_input"),
                )
              }

              // Quick port chips
              Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
              ) {
                Text(
                  text = "Quick Port:",
                  style = MaterialTheme.typography.labelSmall,
                  color = TextMuted,
                )
                listOf("22", "443", "80").forEach { preset ->
                  val selected = sshPortText.trim() == preset
                  MiniChip(
                    text = preset,
                    highlighted = selected,
                    onClick = { sshPortText = preset },
                  )
                }
              }

              OutlinedTextField(
                value = sshUsername,
                onValueChange = { sshUsername = it },
                label = { Text("Username") },
                placeholder = { Text("root", color = TextMuted) },
                singleLine = true,
                colors = fieldColors,
                modifier = Modifier.fillMaxWidth().testTag("ssh_username_input"),
              )

              OutlinedTextField(
                value = sshPassword,
                onValueChange = { sshPassword = it },
                label = { Text("Password") },
                singleLine = true,
                visualTransformation =
                  if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                trailingIcon = {
                  IconButton(onClick = { passwordVisible = !passwordVisible }) {
                    Icon(
                      imageVector =
                        if (passwordVisible) Icons.Rounded.VisibilityOff else Icons.Rounded.Visibility,
                      contentDescription = if (passwordVisible) "Hide password" else "Show password",
                      tint = TextSecondary,
                      modifier = Modifier.size(20.dp),
                    )
                  }
                },
                colors = fieldColors,
                modifier = Modifier.fillMaxWidth().testTag("ssh_password_input"),
              )

              if (isSlowDns) {
                OutlinedTextField(
                  value = slowDnsServerIp,
                  onValueChange = { slowDnsServerIp = it },
                  label = { Text("DNS Server IP") },
                  placeholder = { Text("8.8.8.8 or 1.1.1.1", color = TextMuted) },
                  singleLine = true,
                  colors = fieldColors,
                  modifier = Modifier.fillMaxWidth().testTag("slowdns_ip_input"),
                )

                Row(
                  modifier = Modifier.fillMaxWidth(),
                  horizontalArrangement = Arrangement.spacedBy(8.dp),
                  verticalAlignment = Alignment.CenterVertically,
                ) {
                  Text(
                    text = "Quick DNS:",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMuted,
                  )
                  listOf("8.8.8.8", "1.1.1.1", "9.9.9.9").forEach { preset ->
                    MiniChip(
                      text = preset,
                      highlighted = slowDnsServerIp.trim() == preset,
                      onClick = { slowDnsServerIp = preset },
                    )
                  }
                }

                OutlinedTextField(
                  value = slowDnsNameserver,
                  onValueChange = { slowDnsNameserver = it },
                  label = { Text("Nameserver (NS Domain)") },
                  placeholder = { Text("ns.example.com", color = TextMuted) },
                  singleLine = true,
                  colors = fieldColors,
                  modifier = Modifier.fillMaxWidth().testTag("slowdns_ns_input"),
                )

                OutlinedTextField(
                  value = slowDnsPublicKey,
                  onValueChange = { input ->
                    slowDnsPublicKey = input.filter { !it.isWhitespace() }.take(64)
                  },
                  label = { Text("Public Key (64-char hex)") },
                  placeholder = {
                    Text(
                      text = "0123456789abcdef...",
                      style = MaterialTheme.typography.bodyMedium.copy(fontFamily = JetBrainsMonoFamily, fontSize = 12.sp),
                      color = TextMuted,
                    )
                  },
                  supportingText = {
                    Text(
                      text = "${cleanPubkey.length}/64 hex characters",
                      color = if (isPubkeyValid) EmeraldShield else TextMuted,
                      style = MaterialTheme.typography.labelSmall,
                    )
                  },
                  textStyle =
                    MaterialTheme.typography.bodyMedium.copy(
                      fontFamily = JetBrainsMonoFamily,
                      fontSize = 12.sp,
                    ),
                  minLines = 2,
                  maxLines = 3,
                  colors = fieldColors,
                  modifier = Modifier.fillMaxWidth().testTag("slowdns_pubkey_input"),
                )
              } else {
                OutlinedTextField(
                  value = sshHttpProxy,
                  onValueChange = { sshHttpProxy = it },
                  label = { Text("HTTP Proxy (Optional · IP:Port)") },
                  placeholder = { Text("104.16.0.1:80", color = TextMuted) },
                  singleLine = true,
                  colors = fieldColors,
                  modifier = Modifier.fillMaxWidth().testTag("ssh_proxy_input"),
                )

                OutlinedTextField(
                  value = sshPayload,
                  onValueChange = { sshPayload = it },
                  label = { Text("Payload (Custom HTTP Header)") },
                  placeholder = {
                    Text(
                      text = "GET / HTTP/1.1[crlf]Host: bug.example.com[crlf]Upgrade: websocket[crlf][crlf]",
                      style = MaterialTheme.typography.bodyMedium.copy(fontFamily = JetBrainsMonoFamily, fontSize = 12.sp),
                      color = TextMuted,
                    )
                  },
                  textStyle =
                    MaterialTheme.typography.bodyMedium.copy(
                      fontFamily = JetBrainsMonoFamily,
                      fontSize = 12.sp,
                    ),
                  minLines = 3,
                  maxLines = 5,
                  colors = fieldColors,
                  modifier = Modifier.fillMaxWidth().testTag("ssh_payload_input"),
                )

                Row(
                  modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                  horizontalArrangement = Arrangement.spacedBy(6.dp),
                  verticalAlignment = Alignment.CenterVertically,
                ) {
                  MiniChip(
                    text = "[host_port]",
                    highlighted = false,
                    onClick = { sshPayload += "[host_port]" },
                  )
                  MiniChip(
                    text = "[crlf]",
                    highlighted = false,
                    onClick = { sshPayload += "[crlf]" },
                  )
                  MiniChip(
                    text = "[split]",
                    highlighted = false,
                    onClick = { sshPayload += "[split]" },
                  )
                  MiniChip(
                    text = "WS Sample",
                    highlighted = false,
                    onClick = {
                      val hostToken = sshHost.trim().ifBlank { "[host]" }
                      sshPayload =
                        "GET / HTTP/1.1[crlf]Host: $hostToken[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
                    },
                  )
                }
              }

              if (isSshValid) {
                val parsedProxy =
                  if (isSlowDns) null else VpnLinkParser.parseProxyString(sshHttpProxy)
                OutlinedButton(
                  onClick = {
                    val previewServer =
                      VpnLinkParser.createSshServer(
                        name = sshName,
                        host = sshHost,
                        port = parsedSshPort ?: 22,
                        username = sshUsername,
                        password = sshPassword,
                        payload = sshPayload,
                        sshProxyHost = parsedProxy?.first.orEmpty(),
                        sshProxyPort = parsedProxy?.second ?: 0,
                        sshTunnelMode = sshTunnelMode,
                        slowDnsServerIp = slowDnsServerIp,
                        slowDnsNameserver = slowDnsNameserver,
                        slowDnsPublicKey = slowDnsPublicKey,
                        isCustom = true,
                      )
                    onExportServer(previewServer)
                  },
                  border = BorderStroke(1.dp, CyanPulse.copy(alpha = 0.45f)),
                  colors = ButtonDefaults.outlinedButtonColors(contentColor = CyanPulse),
                  modifier = Modifier.fillMaxWidth().testTag("ssh_dialog_export_button"),
                ) {
                  Icon(
                    imageVector = Icons.Rounded.Share,
                    contentDescription = "Share or export config",
                    modifier = Modifier.size(16.dp),
                  )
                  Spacer(modifier = Modifier.size(6.dp))
                  Text("Share / Export Config", style = MaterialTheme.typography.labelLarge)
                }
              }
            }
          }

          AddServerTab.UDP_ZIVPN -> {
            Column(
              modifier =
                Modifier.fillMaxWidth()
                  .heightIn(max = 420.dp)
                  .verticalScroll(rememberScrollState()),
              verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
              OutlinedTextField(
                value = udpName,
                onValueChange = { udpName = it },
                label = { Text("Server Name / Remark") },
                placeholder = { Text("SG ZIVPN UDP", color = TextMuted) },
                singleLine = true,
                colors = fieldColors,
                modifier = Modifier.fillMaxWidth().testTag("udp_name_input"),
              )

              OutlinedTextField(
                value = udpHost,
                onValueChange = { udpHost = it },
                label = { Text("UDP Server (Host / IP)") },
                placeholder = { Text("157.85.103.29", color = TextMuted) },
                singleLine = true,
                colors = fieldColors,
                modifier = Modifier.fillMaxWidth().testTag("udp_host_input"),
              )

              OutlinedTextField(
                value = udpPortRange,
                onValueChange = { input ->
                  udpPortRange = input.filter { it.isDigit() || it == '-' }.take(11)
                },
                label = { Text("UDP Port / Port Range (Optional)") },
                placeholder = { Text("6000-19999", color = TextMuted) },
                supportingText = {
                  Text(
                    text =
                      if (parsedUdpRange != null) {
                        "Default ZIVPN range: 6000-19999"
                      } else {
                        "Enter a port (e.g. 36712) or range (e.g. 6000-19999)"
                      },
                    color = if (parsedUdpRange != null) TextMuted else AmberConnecting,
                    style = MaterialTheme.typography.labelSmall,
                  )
                },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                colors = fieldColors,
                modifier = Modifier.fillMaxWidth().testTag("udp_port_range_input"),
              )

              OutlinedTextField(
                value = udpPassword,
                onValueChange = { udpPassword = it },
                label = { Text("UDP Password / Auth") },
                placeholder = { Text("zivpn", color = TextMuted) },
                singleLine = true,
                visualTransformation =
                  if (udpPasswordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                trailingIcon = {
                  IconButton(onClick = { udpPasswordVisible = !udpPasswordVisible }) {
                    Icon(
                      imageVector =
                        if (udpPasswordVisible) Icons.Rounded.VisibilityOff else Icons.Rounded.Visibility,
                      contentDescription = if (udpPasswordVisible) "Hide password" else "Show password",
                      tint = TextSecondary,
                      modifier = Modifier.size(20.dp),
                    )
                  }
                },
                colors = fieldColors,
                modifier = Modifier.fillMaxWidth().testTag("udp_password_input"),
              )

              // Receive Window (- / + Stepper, default 2)
              Surface(
                shape = RoundedCornerShape(14.dp),
                color = DeepNavySurface,
                border = BorderStroke(1.dp, SlateOutline),
                modifier = Modifier.fillMaxWidth(),
              ) {
                Row(
                  modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 10.dp),
                  verticalAlignment = Alignment.CenterVertically,
                  horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                  Column(modifier = Modifier.weight(1f)) {
                    Text(
                      text = "Receive Window",
                      style = MaterialTheme.typography.labelLarge,
                      color = TextPrimary,
                    )
                    Text(
                      text =
                        "Conn ${udpReceiveWindow}M · Total ${
                          String.format(Locale.US, "%.1f", udpReceiveWindow * 2.5)
                        }M",
                      style = MaterialTheme.typography.labelSmall.copy(fontFamily = JetBrainsMonoFamily),
                      color = TextMuted,
                    )
                  }
                  Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                  ) {
                    IconButton(
                      onClick = { if (udpReceiveWindow > 1) udpReceiveWindow -= 1 },
                      enabled = udpReceiveWindow > 1,
                      modifier =
                        Modifier.minimumInteractiveComponentSize()
                          .size(44.dp)
                          .clip(RoundedCornerShape(10.dp))
                          .background(ElevatedSlateCard)
                          .border(1.dp, SlateOutline, RoundedCornerShape(10.dp))
                          .testTag("udp_window_minus"),
                    ) {
                      Icon(
                        imageVector = Icons.Rounded.Remove,
                        contentDescription = "Decrease receive window",
                        tint = if (udpReceiveWindow > 1) TextPrimary else TextMuted,
                        modifier = Modifier.size(18.dp),
                      )
                    }
                    Text(
                      text = udpReceiveWindow.toString(),
                      style =
                        MaterialTheme.typography.titleMedium.copy(
                          fontFamily = JetBrainsMonoFamily,
                          fontWeight = FontWeight.Bold,
                        ),
                      color = EmeraldShield,
                      modifier = Modifier.padding(horizontal = 6.dp).testTag("udp_window_value"),
                    )
                    IconButton(
                      onClick = { if (udpReceiveWindow < 64) udpReceiveWindow += 1 },
                      enabled = udpReceiveWindow < 64,
                      modifier =
                        Modifier.minimumInteractiveComponentSize()
                          .size(44.dp)
                          .clip(RoundedCornerShape(10.dp))
                          .background(ElevatedSlateCard)
                          .border(1.dp, SlateOutline, RoundedCornerShape(10.dp))
                          .testTag("udp_window_plus"),
                    ) {
                      Icon(
                        imageVector = Icons.Rounded.Add,
                        contentDescription = "Increase receive window",
                        tint = if (udpReceiveWindow < 64) EmeraldShield else TextMuted,
                        modifier = Modifier.size(18.dp),
                      )
                    }
                  }
                }
              }

              if (isUdpValid) {
                OutlinedButton(
                  onClick = {
                    val previewServer =
                      VpnLinkParser.createUdpServer(
                        name = udpName,
                        host = udpHost,
                        portRange = parsedUdpRange?.first ?: "6000-19999",
                        password = udpPassword,
                        receiveWindow = udpReceiveWindow,
                        isCustom = true,
                      )
                    onExportServer(previewServer)
                  },
                  border = BorderStroke(1.dp, CyanPulse.copy(alpha = 0.45f)),
                  colors = ButtonDefaults.outlinedButtonColors(contentColor = CyanPulse),
                  modifier = Modifier.fillMaxWidth().testTag("udp_dialog_export_button"),
                ) {
                  Icon(
                    imageVector = Icons.Rounded.Share,
                    contentDescription = "Share or export config",
                    modifier = Modifier.size(16.dp),
                  )
                  Spacer(modifier = Modifier.size(6.dp))
                  Text("Share / Export Config", style = MaterialTheme.typography.labelLarge)
                }
              }
            }
          }
        }
      }
    },
    confirmButton = {
      when (activeTab) {
        AddServerTab.V2RAY_LINK -> {
          Button(
            onClick = { onImportLink(linkInput) },
            enabled = linkInput.isNotBlank(),
            colors = ButtonDefaults.buttonColors(containerColor = EmeraldShield, contentColor = ObsidianBg),
            modifier = Modifier.testTag("import_link_confirm_button"),
          ) {
            Text("Import", style = MaterialTheme.typography.labelLarge)
          }
        }
        AddServerTab.SSH_FORM -> {
          Button(
            onClick = {
              onAddSshServer(
                sshName,
                sshHost,
                parsedSshPort ?: 22,
                sshUsername,
                sshPassword,
                sshPayload,
                sshHttpProxy,
                sshTunnelMode,
                slowDnsServerIp,
                slowDnsNameserver,
                slowDnsPublicKey,
                safeEditingServer?.id,
              )
            },
            enabled = isSshValid,
            colors = ButtonDefaults.buttonColors(containerColor = AmberConnecting, contentColor = ObsidianBg),
            modifier = Modifier.testTag("ssh_save_button"),
          ) {
            Text(if (isEditingSsh) "Update SSH" else "Save SSH", style = MaterialTheme.typography.labelLarge)
          }
        }
        AddServerTab.UDP_ZIVPN -> {
          Button(
            onClick = {
              onAddUdpServer(
                udpName,
                udpHost,
                parsedUdpRange?.first ?: "6000-19999",
                udpPassword,
                udpReceiveWindow,
                safeEditingServer?.id,
              )
            },
            enabled = isUdpValid,
            colors = ButtonDefaults.buttonColors(containerColor = EmeraldShield, contentColor = ObsidianBg),
            modifier = Modifier.testTag("udp_save_button"),
          ) {
            Text(if (isEditingUdp) "Update UDP" else "Save UDP", style = MaterialTheme.typography.labelLarge)
          }
        }
      }
    },
    dismissButton = {
      TextButton(onClick = onDismiss) {
        Text("Cancel", color = TextSecondary)
      }
    },
  )
}

@Composable
private fun ProtocolTabButton(
  label: String,
  selected: Boolean,
  accentColor: androidx.compose.ui.graphics.Color,
  onClick: () -> Unit,
  modifier: Modifier = Modifier,
) {
  Box(
    modifier =
      modifier
        .heightIn(min = 42.dp)
        .clip(RoundedCornerShape(10.dp))
        .background(if (selected) accentColor.copy(alpha = 0.18f) else DeepNavySurface)
        .border(
          width = if (selected) 1.dp else 0.dp,
          color = if (selected) accentColor.copy(alpha = 0.5f) else DeepNavySurface,
          shape = RoundedCornerShape(10.dp),
        )
        .clickable(onClick = onClick)
        .padding(horizontal = 6.dp, vertical = 10.dp),
    contentAlignment = Alignment.Center,
  ) {
    Text(
      text = label,
      style =
        MaterialTheme.typography.labelLarge.copy(
          fontSize = 11.5.sp,
          fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
        ),
      color = if (selected) accentColor else TextSecondary,
      maxLines = 1,
      overflow = TextOverflow.Ellipsis,
    )
  }
}

@Composable
private fun MiniChip(
  text: String,
  highlighted: Boolean,
  onClick: () -> Unit,
) {
  Surface(
    shape = RoundedCornerShape(8.dp),
    color = if (highlighted) AmberConnecting.copy(alpha = 0.18f) else DeepNavySurface,
    border =
      BorderStroke(
        1.dp,
        if (highlighted) AmberConnecting.copy(alpha = 0.6f) else SlateOutline,
      ),
    modifier = Modifier.clip(RoundedCornerShape(8.dp)).clickable(onClick = onClick),
  ) {
    Text(
      text = text,
      style = MaterialTheme.typography.labelSmall.copy(fontFamily = JetBrainsMonoFamily),
      color = if (highlighted) AmberConnecting else TextSecondary,
      modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
    )
  }
}
