// =====================================================================
// Screens.kt — واجهات: الرئيسية / النتائج / الملفات / الإعدادات.
// =====================================================================
package com.bahrain.vpnconfigs.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.bahrain.vpnconfigs.data.ResultLine
import com.bahrain.vpnconfigs.engine.TestResult
import java.io.File

@Composable
fun StatCard(label: String, value: String, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(Modifier.padding(14.dp)) {
            Text(label, style = MaterialTheme.typography.labelSmall)
            Text(value, style = MaterialTheme.typography.titleMedium)
        }
    }
}

@Composable
fun HomeScreen(state: UiState, vm: AppViewModel, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("كانفيغات Bahrain", style = MaterialTheme.typography.titleLarge)
        Text(
            "الخادم يجمع ويُقلّص كل 30 دقيقة، وهاتفك يختار الأسرع على شبكتك.",
            style = MaterialTheme.typography.bodyMedium,
        )

        Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
            StatCard("القائمة الحيّة", "${state.configs.size}", Modifier.weight(1f))
            StatCard("آخر تحديث", state.meta.generatedAt.take(16).replace("T", " "), Modifier.weight(1f))
        }

        if (state.meta.byProtocol.isNotEmpty()) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                state.meta.byProtocol.entries.take(4).forEach { (p, n) ->
                    AssistChip(onClick = {}, label = { Text("$p $n") })
                }
            }
        }

        state.error?.let {
            Card(colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.errorContainer)) {
                Text(it, Modifier.padding(12.dp), color = MaterialTheme.colorScheme.onErrorContainer)
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            OutlinedButton(
                onClick = vm::refresh,
                enabled = !state.loading && !state.testing,
            ) {
                Icon(Icons.Filled.Download, null, Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(if (state.loading) "جارٍ التنزيل…" else "تنزيل القائمة")
            }
            if (!state.testing) {
                Button(onClick = vm::startTest, enabled = state.configs.isNotEmpty()) {
                    Icon(Icons.Filled.PlayArrow, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("ابدأ الفحص")
                }
            } else {
                Button(onClick = vm::cancelTest) {
                    Icon(Icons.Filled.Stop, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("إيقاف")
                }
            }
        }

        if (!state.engineReady) {
            Card(colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
                Text(
                    "تنبيه: ملف النواة libsingbox.so غير موجود في هذا البناء، لذلك الفحص معطّل " +
                        "(التنزيل وكتابة الملفات يعملان). راجع README لتجهيز النواة.",
                    Modifier.padding(12.dp),
                )
            }
        }

        state.progress?.let { p ->
            Card {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("${p.stage} — ${p.done}/${p.total}", fontWeight = FontWeight.SemiBold)
                    LinearProgressIndicator(
                        progress = { if (p.total == 0) 0f else p.done.toFloat() / p.total },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text("حيّ حتى الآن: ${p.alive}", style = MaterialTheme.typography.bodyMedium)
                }
            }
        }

        if (state.testing && state.progress == null) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(10.dp))
                Text("جارٍ تجهيز الفحص…")
            }
        }

        if (state.results.isNotEmpty()) {
            Card {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("انتهى الفحص", style = MaterialTheme.typography.titleMedium)
                    Text("نجحت ${state.results.size} عقدة — الأفضل محفوظ في best100.txt")
                    state.bestFile?.let { Text(it.absolutePath, style = MaterialTheme.typography.labelSmall) }
                }
            }
        }
    }
}

@Composable
fun ResultsScreen(state: UiState, modifier: Modifier = Modifier, onCopy: (String) -> Unit) {
    if (state.results.isEmpty()) {
        Column(
            modifier = modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("لا نتائج بعد", style = MaterialTheme.typography.titleMedium)
            Text("نزّل القائمة ثم اضغط «ابدأ الفحص».")
        }
        return
    }
    LazyColumn(modifier = modifier, contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp)) {
        itemsIndexed(state.results, key = { i, r -> "$i-${r.cfg.take(24)}" }) { i, r ->
            ResultRow(i + 1, r, onCopy)
        }
    }
}

@Composable
private fun ResultRow(rank: Int, r: TestResult, onCopy: (String) -> Unit) {
    Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Text("#$rank", fontWeight = FontWeight.Bold, modifier = Modifier.width(44.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    r.cfg.substringBefore("://").uppercase(),
                    style = MaterialTheme.typography.labelSmall,
                )
                Text(
                    com.bahrain.vpnconfigs.engine.Converters.endpointLabel(r.cfg),
                    maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
                Text(
                    "${r.latencyMs}ms • ${if (r.speedKbps > 0) "${r.speedKbps.toInt()}KB/s" else "—"}",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            IconButton(onClick = { onCopy(r.cfg) }) {
                Icon(Icons.Filled.ContentCopy, contentDescription = "نسخ")
            }
        }
    }
}

@Composable
fun FilesScreen(state: UiState, modifier: Modifier = Modifier, onShare: (File) -> Unit) {
    Column(
        modifier = modifier.padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("الملفات", style = MaterialTheme.typography.titleLarge)
        Text(
            "config.txt = كل ما نزّلته، وbest100.txt = أفضل 100 بعد الفحص على شبكتك.",
            style = MaterialTheme.typography.bodyMedium,
        )
        HorizontalDivider()
        FileRow("كل الكانفيغات", "config.txt", state.allFile, onShare)
        FileRow("أفضل 100", "best100.txt", state.bestFile, onShare)
        if (state.allFile == null && state.bestFile == null) {
            Text("لم تُكتب ملفات بعد — شغّل الفحص.", style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun FileRow(title: String, name: String, file: File?, onShare: (File) -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Text(
                    if (file != null) "$name • ${file.length() / 1024} KB"
                    else "$name • غير موجود",
                    style = MaterialTheme.typography.labelSmall,
                )
            }
            IconButton(onClick = { file?.let(onShare) }, enabled = file != null) {
                Icon(Icons.Filled.Share, contentDescription = "مشاركة")
            }
        }
    }
}

@Composable
fun SettingsScreen(vm: AppViewModel, modifier: Modifier = Modifier) {
    val p = vm.settings()
    var owner by remember { mutableStateOf(p.owner) }
    var repo by remember { mutableStateOf(p.repo) }
    var testTop by remember { mutableStateOf(p.testTop.toString()) }
    var speedTop by remember { mutableStateOf(p.speedTop.toString()) }
    var bestN by remember { mutableStateOf(p.bestN.toString()) }
    var conc by remember { mutableStateOf(p.concurrency.toString()) }
    var timeout by remember { mutableStateOf(p.timeoutSec.toString()) }
    var rankSpeed by remember { mutableStateOf(p.rankBySpeed) }
    var auto by remember { mutableStateOf(p.autoRefresh) }

    Column(
        modifier = modifier
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("الإعدادات", style = MaterialTheme.typography.titleLarge)

        OutlinedTextField(
            value = owner, onValueChange = { owner = it },
            label = { Text("اسم المستخدم على GitHub (OWNER)") },
            singleLine = true, modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = repo, onValueChange = { repo = it },
            label = { Text("اسم المستودع (REPO)") },
            singleLine = true, modifier = Modifier.fillMaxWidth(),
        )
        Text(
            "ستُجلب الملفات من:\nhttps://cdn.jsdelivr.net/gh/OWNER/REPO@data/alive.txt",
            style = MaterialTheme.typography.labelSmall,
        )

        HorizontalDivider()
        Text("الفحص", style = MaterialTheme.typography.titleMedium)
        NumberField("عدد الكانفيغات المفحوصة", testTop) { testTop = it }
        NumberField("عدد العُقد لقياس السرعة", speedTop) { speedTop = it }
        NumberField("عدد النتائج في best100", bestN) { bestN = it }
        NumberField("التوازي (1-12)", conc) { conc = it }
        NumberField("مهلة الاتصال بالثواني", timeout) { timeout = it }

        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = rankSpeed, onCheckedChange = { rankSpeed = it })
            Spacer(Modifier.width(10.dp))
            Text("الترتيب حسب السرعة (بدل التأخير)")
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = auto, onCheckedChange = { auto = it })
            Spacer(Modifier.width(10.dp))
            Text("تحديث القائمة تلقائيًا كل ساعة")
        }

        Button(
            onClick = {
                vm.saveSettings(
                    owner, repo,
                    testTop.toIntOrNull() ?: 600,
                    speedTop.toIntOrNull() ?: 120,
                    bestN.toIntOrNull() ?: 100,
                    (conc.toIntOrNull() ?: 6).coerceIn(1, 12),
                    timeout.toIntOrNull() ?: 6,
                    rankSpeed, auto,
                )
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("حفظ الإعدادات") }
    }
}

@Composable
private fun NumberField(label: String, value: String, onChange: (String) -> Unit) {
    OutlinedTextField(
        value = value,
        onValueChange = { onChange(it.filter { c -> c.isDigit() }) },
        label = { Text(label) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        modifier = Modifier.fillMaxWidth(),
    )
}
