// ملف الجذر: الإضافات مُعرَّفة في app/build.gradle.kts
tasks.register("clean", Delete::class) { delete(rootProject.layout.buildDirectory) }
