package com.example.ui

import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.LockOpen
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.ui.theme.AmberConnecting
import com.example.ui.theme.CyanPulse
import com.example.ui.theme.DeepNavySurface
import com.example.ui.theme.ElevatedSlateCard
import com.example.ui.theme.EmeraldShield
import com.example.ui.theme.ObsidianBg
import com.example.ui.theme.SlateOutline
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.example.vpn.model.VpnServer
import com.example.vpn.parser.VpnLinkParser
import java.nio.charset.StandardCharsets

@Composable
fun ExportConfigDialog(
  server: VpnServer,
  onDismiss: () -> Unit,
  onCopyUri: (String, Boolean) -> Unit,
  onShareUri: (String, String) -> Unit,
  onShowMessage: (String) -> Unit,
) {
  val context = LocalContext.current
  var lockConfig by remember(server.id) { mutableStateOf(false) }

  val saveFileLauncher =
    rememberLauncherForActivityResult(
      contract = ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri: Uri? ->
      if (uri != null) {
        val content = VpnLinkParser.toShareUri(server, locked = lockConfig)
        val saved = writeTextToUri(context, uri, content)
        if (saved) {
          val mode = if (lockConfig) "AES-Encrypted" else "Standard"
          onShowMessage("Exported $mode config file for ${server.name}")
          onDismiss()
        } else {
          onShowMessage("Failed to write config file.")
        }
      }
    }

  AlertDialog(
    onDismissRequest = onDismiss,
    containerColor = ElevatedSlateCard,
    titleContentColor = TextPrimary,
    textContentColor = TextSecondary,
    title = {
      Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
          imageVector = if (lockConfig) Icons.Rounded.Lock else Icons.Rounded.Share,
          contentDescription = null,
          tint = if (lockConfig) AmberConnecting else CyanPulse,
          modifier = Modifier.size(22.dp),
        )
        Spacer(modifier = Modifier.width(10.dp))
        Text(
          text = "Share / Export Config",
          style = MaterialTheme.typography.titleLarge,
        )
      }
    },
    text = {
      Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
      ) {
        // Server summary header (never leaks host/IP/credentials)
        Surface(
          shape = RoundedCornerShape(14.dp),
          color = DeepNavySurface,
          border = BorderStroke(1.dp, SlateOutline),
          modifier = Modifier.fillMaxWidth(),
        ) {
          Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
            Text(
              text = server.name,
              style = MaterialTheme.typography.titleMedium,
              color = TextPrimary,
              maxLines = 1,
              overflow = TextOverflow.Ellipsis,
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
              text = "${server.protocol.displayName} • ${if (lockConfig) "AES-256 Protected" else "Standard Config"}",
              style = MaterialTheme.typography.labelSmall,
              color = if (lockConfig) AmberConnecting else TextSecondary,
            )
          }
        }

        // Lock Config Checkbox Card
        Surface(
          shape = RoundedCornerShape(14.dp),
          color = if (lockConfig) AmberConnecting.copy(alpha = 0.12f) else DeepNavySurface,
          border =
            BorderStroke(
              1.dp,
              if (lockConfig) AmberConnecting.copy(alpha = 0.55f) else SlateOutline,
            ),
          modifier =
            Modifier.fillMaxWidth()
              .clip(RoundedCornerShape(14.dp))
              .clickable { lockConfig = !lockConfig }
              .testTag("lock_config_row"),
        ) {
          Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
          ) {
            Checkbox(
              checked = lockConfig,
              onCheckedChange = { lockConfig = it },
              colors =
                CheckboxDefaults.colors(
                  checkedColor = AmberConnecting,
                  uncheckedColor = TextSecondary,
                  checkmarkColor = ObsidianBg,
                ),
              modifier = Modifier.testTag("lock_config_checkbox"),
            )
            Spacer(modifier = Modifier.width(6.dp))
            Column(modifier = Modifier.weight(1f)) {
              Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                  imageVector = if (lockConfig) Icons.Rounded.Lock else Icons.Rounded.LockOpen,
                  contentDescription = null,
                  tint = if (lockConfig) AmberConnecting else TextSecondary,
                  modifier = Modifier.size(16.dp),
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                  text = "Lock Config (ဖိုင်လော့ခ်ချမည်)",
                  style = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.Bold),
                  color = if (lockConfig) AmberConnecting else TextPrimary,
                )
              }
              Spacer(modifier = Modifier.height(3.dp))
              Text(
                text =
                  if (lockConfig) {
                    "Encrypts all server details with AES-256 and disables Edit, Copy & Share after import."
                  } else {
                    "Exports an unlocked share link or file that can be viewed and edited."
                  },
                style = MaterialTheme.typography.bodySmall,
                color = TextSecondary,
              )
            }
          }
        }

        // Export / Share Action Buttons
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          OutlinedButton(
            onClick = {
              val uri = VpnLinkParser.toShareUri(server, locked = lockConfig)
              onCopyUri(uri, lockConfig)
              onDismiss()
            },
            border = BorderStroke(1.dp, CyanPulse.copy(alpha = 0.5f)),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = CyanPulse),
            modifier = Modifier.weight(1f).testTag("export_copy_link_button"),
          ) {
            Icon(
              imageVector = Icons.Rounded.ContentCopy,
              contentDescription = "Copy Link",
              modifier = Modifier.size(17.dp),
            )
            Spacer(modifier = Modifier.width(6.dp))
            Text("Copy", style = MaterialTheme.typography.labelLarge)
          }

          Button(
            onClick = {
              val uri = VpnLinkParser.toShareUri(server, locked = lockConfig)
              onShareUri(uri, server.name)
              onDismiss()
            },
            colors =
              ButtonDefaults.buttonColors(
                containerColor = if (lockConfig) AmberConnecting else EmeraldShield,
                contentColor = ObsidianBg,
              ),
            modifier = Modifier.weight(1f).testTag("export_share_link_button"),
          ) {
            Icon(
              imageVector = Icons.Rounded.Share,
              contentDescription = "Share Link",
              modifier = Modifier.size(17.dp),
            )
            Spacer(modifier = Modifier.width(6.dp))
            Text("Share", style = MaterialTheme.typography.labelLarge)
          }
        }

        OutlinedButton(
          onClick = {
            val safeName =
              server.name
                .replace(Regex("[^A-Za-z0-9._-]"), "_")
                .trim('_')
                .ifBlank { "pao_tunnel_config" }
            saveFileLauncher.launch("$safeName.pao")
          },
          border = BorderStroke(1.dp, SlateOutline),
          colors = ButtonDefaults.outlinedButtonColors(contentColor = TextPrimary),
          modifier = Modifier.fillMaxWidth().testTag("export_save_file_button"),
        ) {
          Icon(
            imageVector = Icons.Rounded.FileDownload,
            contentDescription = "Save Config File",
            tint = if (lockConfig) AmberConnecting else CyanPulse,
            modifier = Modifier.size(18.dp),
          )
          Spacer(modifier = Modifier.width(8.dp))
          Text(
            text = if (lockConfig) "Export Locked File (.pao)" else "Export File (.pao)",
            style = MaterialTheme.typography.labelLarge,
          )
        }

        if (lockConfig) {
          Text(
            text = "Only PAO Tunnel can decrypt and connect using paolock:// files & links.",
            style = MaterialTheme.typography.labelSmall,
            color = TextMuted,
          )
        }
      }
    },
    confirmButton = {},
    dismissButton = {
      TextButton(onClick = onDismiss) {
        Text("Close", color = TextSecondary)
      }
    },
  )
}

private fun writeTextToUri(context: Context, uri: Uri, content: String): Boolean {
  return runCatching {
      context.contentResolver.openOutputStream(uri)?.use { out ->
        out.write(content.toByteArray(StandardCharsets.UTF_8))
        out.flush()
      } ?: return false
      true
    }
    .getOrDefault(false)
}
