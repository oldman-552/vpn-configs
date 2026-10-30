// =====================================================================
// PromoModels.kt — نماذج بيانات نظام الإعلانات المتناوبة عند فتح التطبيق.
// =====================================================================
package com.bahrain.vpnconfigs.data

import java.io.File

data class PromoItem(
    val id: String,
    val enabled: Boolean = true,
    val image: String,
    val title: String = "",
    val link: String = "",
    val buttonText: String = "",
)

data class PromoManifest(
    val enabled: Boolean = true,
    val closeDelaySec: Int = 3,
    val ads: List<PromoItem> = emptyList(),
)

data class ResolvedPromoBanner(
    val id: String,
    val imageFile: File,
    val title: String = "",
    val link: String = "",
    val buttonText: String = "",
    val closeDelaySec: Int = 3,
    val slotIndex: Int = 0,
    val totalSlots: Int = 1,
)
