// =====================================================================
// Screens.kt — واجهات: الرئيسية / النتائج / الملفات / الإعدادات.
// =====================================================================
package com.bahrain.vpnconfigs.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
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
import com.bahrain.vpnconfigs.data.Repo
import com.bahrain.vpnconfigs.engine.Converters
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
            Text(value, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
fun HomeScreen(
    state: UiState,
    vm: AppViewModel,
    modifier: Modifier = Modifier,
    onCopy: (String, String) -> Unit,
    onOpenUri: (String) -> Unit,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("كانفيغات Bahrain", style = MaterialTheme.typography.titleLarge)
        Text(
            "الخادم يجمع ويُقلّص كل 30 دقيقة، وهاتفك يختار الأسرع فعليًا على شبكتك.",
            style = MaterialTheme.typography.bodyMedium,
        )

        Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
            StatCard("القائمة الحيّة", "${state.configs.size}", Modifier.weight(1f))
            StatCard(
                "آخر تحديث",
                state.meta.generatedAt.take(16).replace("T", " "),
                Modifier.weight(1f),
            )
        }

        if (state.meta.byProtocol.isNotEmpty()) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
            ) {
                state.meta.byProtocol.entries.forEach { (p, n) ->
                    AssistChip(onClick = {}, label = { Text("$p $n") })
                }
            }
        }

        state.error?.let {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer
                ),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(it, Modifier.padding(12.dp), color = MaterialTheme.colorScheme.onErrorContainer)
            }
        }

        state.info?.let {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer
                ),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(it, Modifier.padding(12.dp), color = MaterialTheme.colorScheme.onPrimaryContainer)
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
                Button(
                    onClick = vm::startTest,
                    enabled = state.configs.isNotEmpty() && state.engineReady,
                ) {
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
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                ),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    "تنبيه: ملف النواة libsingbox.so غير موجود في هذا البناء، لذلك الفحص المحلي معطّل " +
                        "(التنزيل وروابط الاشتراك المباشرة تعمل بشكل طبيعي).",
                    Modifier.padding(12.dp),
                )
            }
        }

        state.progress?.let { p ->
            Card(Modifier.fillMaxWidth()) {
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
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("آخر نتيجة فحص على شبكتك", style = MaterialTheme.typography.titleMedium)
                    Text("نجحت ${state.results.size} عقدة — الأفضل محفوظ في best100.txt و sub.txt")
                    OutlinedButton(
                        onClick = {
                            val topText = state.results.take(vm.settings().bestN)
                                .mapIndexed { i, r ->
                                    val sp = if (r.speedKbps > 0) "${r.speedKbps.toInt()}KB/s" else "—"
                                    "${r.cfg}#${i + 1} | ${r.latencyMs}ms | $sp"
                                }
                                .joinToString("\n")
                            onCopy(topText, "نُسخ أفضل ${minOf(state.results.size, vm.settings().bestN)} كانفيغ للحافظة")
                        },
                    ) {
                        Icon(Icons.Filled.ContentCopy, null, Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("نسخ أفضل النتائج للاستيراد في v2rayNG / Hiddify")
                    }
                }
            }
        }

        if (state.subUrl.isNotBlank()) {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("اشتراك سحابي مباشر (يتحدث كل 30 دقيقة)", style = MaterialTheme.typography.titleMedium)
                    Text(state.subUrl, style = MaterialTheme.typography.labelSmall)
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.horizontalScroll(rememberScrollState()),
                    ) {
                        OutlinedButton(onClick = { onCopy(state.subUrl, "نُسخ رابط الاشتراك") }) {
                            Icon(Icons.Filled.Link, null, Modifier.size(16.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("نسخ الرابط")
                        }
                        OutlinedButton(
                            onClick = { onOpenUri("hiddify://import/${state.subUrl}#BahrainConfigs") },
                        ) {
                            Icon(Icons.AutoMirrored.Filled.OpenInNew, null, Modifier.size(16.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("فتح في Hiddify")
                        }
                        OutlinedButton(
                            onClick = { onOpenUri("v2rayng://install-sub?url=${android.net.Uri.encode(state.subUrl)}&name=BahrainConfigs") },
                        ) {
                            Icon(Icons.AutoMirrored.Filled.OpenInNew, null, Modifier.size(16.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("فتح في v2rayNG")
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ResultsScreen(
    state: UiState,
    modifier: Modifier = Modifier,
    onCopy: (String, String) -> Unit,
    onOpenUri: (String) -> Unit,
) {
    if (state.results.isEmpty()) {
        Column(
            modifier = modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("لا نتائج بعد", style = MaterialTheme.typography.titleMedium)
            Text("نزّل القائمة ثم اضغط «ابدأ الفحص» لاختيار الأسرع على شبكتك.")
        }
        return
    }

    var selectedProto by remember { mutableStateOf("ALL") }
    val protocols = remember(state.results) {
        val counts = LinkedHashMap<String, Int>()
        state.results.forEach { r ->
            val s = Converters.schemeOf(r.cfg).uppercase()
            counts[s] = (counts[s] ?: 0) + 1
        }
        counts
    }
    val filtered = remember(state.results, selectedProto) {
        if (selectedProto == "ALL") state.results
        else state.results.filter { Converters.schemeOf(it.cfg).equals(selectedProto, ignoreCase = true) }
    }

    Column(modifier = modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            FilterChip(
                selected = selectedProto == "ALL",
                onClick = { selectedProto = "ALL" },
                label = { Text("الكل (${state.results.size})") },
            )
            protocols.forEach { (proto, count) ->
                FilterChip(
                    selected = selectedProto == proto,
                    onClick = { selectedProto = proto },
                    label = { Text("$proto ($count)") },
                )
            }
        }

        LazyColumn(
            modifier = Modifier.weight(1f),
            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
        ) {
            itemsIndexed(filtered, key = { i, r -> "$i-${r.cfg.hashCode()}" }) { i, r ->
                ResultRow(
                    rank = i + 1,
                    r = r,
                    onCopy = { cfg -> onCopy(cfg, "نُسخ الكانفيغ") },
                    onOpen = { cfg -> onOpenUri(cfg) },
                )
            }
        }
    }
}

@Composable
private fun ResultRow(
    rank: Int,
    r: TestResult,
    onCopy: (String) -> Unit,
    onOpen: (String) -> Unit,
) {
    val speedTxt = if (r.speedKbps > 0) "${r.speedKbps.toInt()}KB/s" else "—"
    val fullCfg = "${r.cfg}#$rank | ${r.latencyMs}ms | $speedTxt"
    Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Text("#$rank", fontWeight = FontWeight.Bold, modifier = Modifier.width(44.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    Converters.schemeOf(r.cfg).uppercase(),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary,
                )
                Text(
                    Converters.endpointLabel(r.cfg),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    "${r.latencyMs}ms • $speedTxt",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            IconButton(onClick = { onCopy(fullCfg) }) {
                Icon(Icons.Filled.ContentCopy, contentDescription = "نسخ")
            }
            IconButton(onClick = { onOpen(fullCfg) }) {
                Icon(Icons.AutoMirrored.Filled.OpenInNew, contentDescription = "فتح في تطبيق VPN")
            }
        }
    }
}

@Composable
fun FilesScreen(
    state: UiState,
    modifier: Modifier = Modifier,
    onCopyFile: (File) -> Unit,
    onShare: (File) -> Unit,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("الملفات", style = MaterialTheme.typography.titleLarge)
        Text(
            "انسخ المحتوى مباشرة للاستيراد من الحافظة في v2rayNG / Hiddify / NekoBox، أو شارك الملف.",
            style = MaterialTheme.typography.bodyMedium,
        )
        HorizontalDivider()
        FileRow("أفضل 100 على شبكتك", "best100.txt", state.bestFile, onCopyFile, onShare)
        FileRow("اشتراك Base64 المحلي", "sub.txt", state.subFile, onCopyFile, onShare)
        FileRow("كل الكانفيغات الحيّة", "config.txt", state.allFile, onCopyFile, onShare)
        if (state.allFile == null && state.bestFile == null) {
            Text("نزّل القائمة أو شغّل الفحص لإنشاء الملفات.", style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun FileRow(
    title: String,
    name: String,
    file: File?,
    onCopyFile: (File) -> Unit,
    onShare: (File) -> Unit,
) {
    val exists = file != null && file.exists()
    Card(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Text(
                    if (exists && file != null) "$name • ${maxOf(1L, file.length() / 1024)} KB"
                    else "$name • غير متوفّر بعد",
                    style = MaterialTheme.typography.labelSmall,
                )
            }
            IconButton(onClick = { file?.let(onCopyFile) }, enabled = exists) {
                Icon(Icons.Filled.ContentCopy, contentDescription = "نسخ المحتوى")
            }
            IconButton(onClick = { file?.let(onShare) }, enabled = exists) {
                Icon(Icons.Filled.Share, contentDescription = "مشاركة")
            }
        }
    }
}

@Composable
fun SettingsScreen(vm: AppViewModel, state: UiState, modifier: Modifier = Modifier) {
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

    val previewOwner = owner.trim().ifBlank { Repo.DEFAULT_OWNER }
    val previewRepo = repo.trim().ifBlank { Repo.DEFAULT_REPO }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("الإعدادات", style = MaterialTheme.typography.titleLarge)

        state.info?.let {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer
                ),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(it, Modifier.padding(12.dp), color = MaterialTheme.colorScheme.onPrimaryContainer)
            }
        }

        OutlinedTextField(
            value = owner,
            onValueChange = { owner = it },
            label = { Text("اسم المستخدم على GitHub (OWNER)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = repo,
            onValueChange = { repo = it },
            label = { Text("اسم المستودع (REPO)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Text(
            "ستُجلب الملفات من:\nhttps://cdn.jsdelivr.net/gh/$previewOwner/$previewRepo@data/alive.txt",
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
                    owner.ifBlank { Repo.DEFAULT_OWNER },
                    repo.ifBlank { Repo.DEFAULT_REPO },
                    testTop.toIntOrNull() ?: 600,
                    speedTop.toIntOrNull() ?: 120,
                    bestN.toIntOrNull() ?: 100,
                    (conc.toIntOrNull() ?: 6).coerceIn(1, 12),
                    (timeout.toIntOrNull() ?: 6).coerceIn(2, 30),
                    rankSpeed,
                    auto,
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
