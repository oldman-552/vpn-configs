// =====================================================================
// AppViewModel.kt — حالة التطبيق وكل العمليات (تنزيل / فحص / كتابة ملفات).
// =====================================================================
package com.bahrain.vpnconfigs.ui

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.data.RemoteMeta
import com.bahrain.vpnconfigs.data.Repo
import com.bahrain.vpnconfigs.data.ResultLine
import com.bahrain.vpnconfigs.engine.TestProgress
import com.bahrain.vpnconfigs.engine.TestResult
import com.bahrain.vpnconfigs.engine.Tester
import com.bahrain.vpnconfigs.work.RefreshWorker
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.TimeUnit

data class UiState(
    val loading: Boolean = false,
    val testing: Boolean = false,
    val configs: List<String> = emptyList(),
    val meta: RemoteMeta = RemoteMeta(),
    val source: String = "—",
    val error: String? = null,
    val info: String? = null,
    val progress: TestProgress? = null,
    val results: List<TestResult> = emptyList(),
    val bestFile: File? = null,
    val subFile: File? = null,
    val allFile: File? = null,
    val engineReady: Boolean = false,
    val subUrl: String = "",
)

class AppViewModel(app: Application) : AndroidViewModel(app) {

    private val prefs = Prefs(app)
    private val tester = Tester(app)

    var state by mutableStateOf(
        UiState(
            engineReady = tester.engineAvailable,
            subUrl = buildRepo().subscriptionUrl,
        )
    )
        private set

    private var testJob: Job? = null

    init {
        viewModelScope.launch {
            val r = buildRepo()
            val cached = withContext(Dispatchers.IO) { r.loadCached() }
            val savedResults = withContext(Dispatchers.IO) { r.loadSavedBest() }
            val allF = withContext(Dispatchers.IO) { r.existingAllFile() }
            val bestF = withContext(Dispatchers.IO) { r.existingBestFile() }
            val subF = withContext(Dispatchers.IO) { r.existingSubFile() }

            state = state.copy(
                configs = cached?.configs ?: emptyList(),
                meta = cached?.meta ?: RemoteMeta(),
                source = cached?.source ?: "—",
                results = savedResults,
                allFile = allF,
                bestFile = bestF,
                subFile = subF,
                engineReady = tester.engineAvailable,
                subUrl = r.subscriptionUrl,
            )

            if (cached == null) {
                refresh()
            }
        }
    }

    private fun buildRepo(): Repo {
        val owner = prefs.owner.ifBlank { Repo.DEFAULT_OWNER }
        val rep = prefs.repo.ifBlank { Repo.DEFAULT_REPO }
        return Repo(getApplication(), owner, rep)
    }

    // ── تنزيل القائمة الحيّة ──
    fun refresh() {
        val r = buildRepo()
        state = state.copy(loading = true, error = null, info = null, subUrl = r.subscriptionUrl)
        viewModelScope.launch {
            val res = withContext(Dispatchers.IO) { r.loadRemote() }
            val allFile = if (res.configs.isNotEmpty()) {
                withContext(Dispatchers.IO) { runCatching { r.writeAll(res.configs) }.getOrNull() }
            } else {
                state.allFile
            }
            state = state.copy(
                loading = false,
                configs = res.configs.ifEmpty { state.configs },
                meta = if (res.meta.generatedAt != "—") res.meta else state.meta,
                source = res.source,
                allFile = allFile,
                error = res.error,
            )
        }
    }

    // ── الفحص الحقيقي على شبكة الهاتف ──
    fun startTest() {
        if (state.configs.isEmpty()) {
            state = state.copy(error = "نزّل القائمة أولًا بالضغط على «تنزيل القائمة»")
            return
        }
        if (!tester.engineAvailable) {
            state = state.copy(error = "نواة sing-box غير مثبتة في هذا البناء (libsingbox.so مفقود)")
            return
        }
        testJob?.cancel()
        val snapshotConfigs = state.configs
        state = state.copy(testing = true, error = null, info = null, progress = null)
        testJob = viewModelScope.launch {
            try {
                val results = tester.run(
                    configs = snapshotConfigs,
                    testTop = prefs.testTop,
                    speedTop = prefs.speedTop,
                    concurrency = prefs.concurrency,
                    timeoutSec = prefs.timeoutSec,
                    rankBySpeed = prefs.rankBySpeed,
                ) { p ->
                    withContext(Dispatchers.Main.immediate) {
                        state = state.copy(progress = p)
                    }
                }

                val r = buildRepo()
                val allFile = withContext(Dispatchers.IO) {
                    runCatching { r.writeAll(snapshotConfigs) }.getOrNull()
                }
                val bestPair = if (results.isNotEmpty()) {
                    withContext(Dispatchers.IO) {
                        runCatching {
                            r.writeBest(
                                results.map { ResultLine(it.cfg, it.latencyMs, it.speedKbps) },
                                prefs.bestN,
                            )
                        }.getOrNull()
                    }
                } else null

                state = state.copy(
                    testing = false,
                    results = results,
                    progress = null,
                    allFile = allFile ?: state.allFile,
                    bestFile = bestPair?.first ?: state.bestFile,
                    subFile = bestPair?.second ?: state.subFile,
                    error = if (results.isEmpty()) "لم تنجح أي عقدة — جرّب زيادة المهلة أو تحديث القائمة" else null,
                )
            } catch (_: CancellationException) {
                state = state.copy(testing = false, progress = null, info = "تم إيقاف الفحص")
            } catch (e: Exception) {
                state = state.copy(
                    testing = false,
                    progress = null,
                    error = "خطأ أثناء الفحص: ${e.localizedMessage ?: e.javaClass.simpleName}",
                )
            }
        }
    }

    fun cancelTest() {
        testJob?.cancel()
        state = state.copy(testing = false, progress = null, info = "تم إيقاف الفحص")
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

        val wm = WorkManager.getInstance(getApplication())
        if (autoRefresh) {
            val req = PeriodicWorkRequestBuilder<RefreshWorker>(1, TimeUnit.HOURS).build()
            wm.enqueueUniquePeriodicWork("refresh", ExistingPeriodicWorkPolicy.KEEP, req)
        } else {
            wm.cancelUniqueWork("refresh")
        }

        val r = buildRepo()
        state = state.copy(
            error = null,
            info = "تم حفظ الإعدادات بنجاح",
            subUrl = r.subscriptionUrl,
        )
    }

    fun settings() = prefs
}
