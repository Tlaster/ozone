@Suppress("DSL_SCOPE_VIOLATION")
plugins {
  kotlin("jvm") version libs.versions.kotlin
  id("ozone-base")
  id("ozone-publish")
  id("com.github.gmazzo.buildconfig") version libs.versions.buildconfig
  id("com.google.devtools.ksp") version libs.versions.ksp
  `kotlin-dsl`
}

setProperty("POM_NAME", "AT Protocol for Kotlin Generator")
setProperty("POM_DESCRIPTION", "Gradle Plugin to generate AT Protocol classes.")

dependencies {
  api(kotlin("gradle-plugin"))
  api(libs.kotlinpoet)
  api(libs.moshi)
  api(libs.moshi.adapters)

  ksp(libs.moshi.codegen)
}

gradlePlugin {
  plugins {
    create("generator") {
      id = "sh.christian.ozone.generator"
      implementationClass = "sh.christian.ozone.api.gradle.LexiconGeneratorPlugin"
    }
  }
}

buildConfig {
  packageName("sh.christian.ozone.buildconfig")

  useKotlinOutput {
    internalVisibility = true
  }

  forClass("Dependencies") {
    buildConfigField("String", "KOTLINX_DATETIME", "\"${libs.versions.kotlinx.datetime.get()}\"")
    buildConfigField("String", "KOTLINX_SERIALIZATION", "\"${libs.versions.serialization.get()}\"")
    buildConfigField("String", "KTOR", "\"${libs.versions.ktor.get()}\"")
  }
}
