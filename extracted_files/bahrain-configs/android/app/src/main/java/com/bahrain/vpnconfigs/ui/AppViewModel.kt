// =====================================================================
// AppViewModel.kt — حالة التطبيق وكل العمليات (تنزيل / فحص / كتابة ملفات).
// =====================================================================
package com.bahrain.vpnconfigs.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.data.RemoteMeta
import com.bahrain.vpnconfigs.data.Repo
import com.bahrain.vpnconfigs.data.ResultLine
import com.bahrain.vpnconfigs.engine.TestProgress
import com.bahrain.vpnconfigs.engine.TestResult
import com.bahrain.vpnconfigs.engine.Tester
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import java.io.File

data class UiState(
    val loading: Boolean = false,
    val testing: Boolean = false,
    val configs: List<String> = emptyList(),
    val meta: RemoteMeta = RemoteMeta(),
    val source: String = "—",
    val error: String? = null,
    val progress: TestProgress? = null,
    val results: List<TestResult> = emptyList(),
    val bestFile: File? = null,
    val allFile: File? = null,
    val engineReady: Boolean = false,
)

class AppViewModel(app: Application) : AndroidViewModel(app) {

    private val prefs = Prefs(app)
    private val tester = Tester(app)

    var state by androidx.compose.runtime.mutableStateOf(UiState(engineReady = tester.engineAvailable))
        private set

    private var testJob: Job? = null

    private fun repo(): Repo? {
        val owner = prefs.owner.ifBlank { Repo.DEFAULT_OWNER }
        val rep = prefs.repo.ifBlank { Repo.DEFAULT_REPO }
        if (owner == Repo.DEFAULT_OWNER || rep == Repo.DEFAULT_REPO) return null
        return Repo(getApplication(), owner, rep)
    }

    // ── تنزيل القائمة الحيّة ──
    fun refresh() {
        val r = repo() ?: run {
            state = state.copy(error = "اضبط اسم المستودع في الإعدادات أولًا (OWNER/REPO)")
            return
        }
        state = state.copy(loading = true, error = null)
        viewModelScope.launch {
            val res = r.loadRemote()
            state = state.copy(
                loading = false,
                configs = res.configs,
                meta = res.meta,
                source = res.source,
                error = res.error,
            )
        }
    }

    // ── الفحص الحقيقي على شبكة الهاتف ──
    fun startTest() {
        if (state.configs.isEmpty()) {
            state = state.copy(error = "نزّل القائمة أولًا")
            return
        }
        if (!tester.engineAvailable) {
            state = state.copy(error = "نواة sing-box غير مثبتة في هذا البناء (libsingbox.so مفقود)")
            return
        }
        testJob?.cancel()
        state = state.copy(testing = true, error = null, results = emptyList(), progress = null)
        testJob = viewModelScope.launch {
            val results = tester.run(
                configs = state.configs,
                testTop = prefs.testTop,
                speedTop = prefs.speedTop,
                concurrency = prefs.concurrency,
                timeoutSec = prefs.timeoutSec,
                rankBySpeed = prefs.rankBySpeed,
            ) { p -> state = state.copy(progress = p) }

            val allFile = repo()?.let { r ->
                runCatching { r.writeAll(state.configs) }.getOrNull()
            }
            val bestFile = repo()?.let { r ->
                runCatching {
                    r.writeBest(
                        results.map { ResultLine(it.cfg, it.latencyMs, it.speedKbps) },
                        prefs.bestN,
                    )
                }.getOrNull()
            }
            state = state.copy(
                testing = false,
                results = results,
                progress = null,
                allFile = allFile,
                bestFile = bestFile,
                error = if (results.isEmpty()) "لم تنجح أي عقدة — جرّب زيادة المهلة أو تغيير الشبكة" else null,
            )
        }
    }

    fun cancelTest() {
        testJob?.cancel()
        state = state.copy(testing = false, progress = null)
    }

    // ── إعدادات ──
    fun saveSettings(
        owner: String, repoName: String, testTop: Int, speedTop: Int, bestN: Int,
        concurrency: Int, timeoutSec: Int, rankBySpeed: Boolean, autoRefresh: Boolean,
    ) {
        prefs.owner = owner
        prefs.repo = repoName
        prefs.testTop = testTop
        prefs.speedTop = speedTop
        prefs.bestN = bestN
        prefs.concurrency = concurrency
        prefs.timeoutSec = timeoutSec
        prefs.rankBySpeed = rankBySpeed
        prefs.autoRefresh = autoRefresh
        state = state.copy(error = null)
    }

    fun settings() = prefs

    fun engineAvailable() = tester.engineAvailable
}
