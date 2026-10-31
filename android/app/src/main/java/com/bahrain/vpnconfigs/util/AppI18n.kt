// =====================================================================
// AppI18n.kt — محرّك اللغات الثنائي لتطبيق bahrain-vpn (v1):
//   • اللغة العربية (AR / RTL) هي اللغة الأساسية والافتراضية دائمًا.
//   • يدعم التبديل الفوري الحي إلى الإنجليزية (EN / LTR) دون إعادة تشغيل التطبيق.
// =====================================================================
package com.bahrain.vpnconfigs.util

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.unit.LayoutDirection
import com.bahrain.vpnconfigs.data.Prefs

enum class AppLang(
    val code: String,
    val layoutDirection: LayoutDirection,
    val nativeLabel: String,
) {
    AR("ar", LayoutDirection.Rtl, "العربية"),
    EN("en", LayoutDirection.Ltr, "English");

    companion object {
        val DEFAULT: AppLang = AR

        fun fromCode(raw: String?): AppLang = when (raw?.trim()?.lowercase()) {
            "en", "english" -> EN
            else -> AR
        }
    }
}

object AppI18n {

    @Volatile
    private var fastLang: AppLang = AppLang.AR

    var current: AppLang by mutableStateOf(AppLang.AR)
        private set

    val isEnglish: Boolean
        get() = current == AppLang.EN

    val isArabic: Boolean
        get() = current == AppLang.AR

    fun initFromPrefs(ctx: Context): AppLang {
        val loaded = AppLang.fromCode(Prefs(ctx).appLanguage)
        fastLang = loaded
        current = loaded
        return loaded
    }

    fun setLanguage(ctx: Context, lang: AppLang) {
        Prefs(ctx).appLanguage = lang.code
        fastLang = lang
        current = lang
    }

    fun toggleLanguage(ctx: Context): AppLang {
        val next = if (fastLang == AppLang.AR) AppLang.EN else AppLang.AR
        setLanguage(ctx, next)
        return next
    }

    fun setLanguageDirectForTest(lang: AppLang) {
        fastLang = lang
        current = lang
    }
}

/**
 * دالة الترجمة الفورية: تعيد النص العربي افتراضيًا (اللغة الأساسية) أو الإنجليزي عند اختيار EN.
 * قراءة `AppI18n.current` داخل دوال `@Composable` تجعل الواجهة تتحدّث لحظيًا عند تغيير اللغة.
 */
fun tr(ar: String, en: String): String =
    if (AppI18n.current == AppLang.EN) en else ar
