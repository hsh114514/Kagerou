plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "r5gk.boot"
    compileSdk {
        version = release(36)
    }

    defaultConfig {
        applicationId = "r5gk.boot"
        minSdk = 26
        // 28 on purpose: untrusted_app_27 keeps exec on app_data_file and the
        // looser seccomp filter, both of which the exploit child needs.
        targetSdk = 28
        versionCode = 23
        versionName = "2.3"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }

    // Sideloaded only: the old targetSdk is what keeps exec on app_data_file
    // (and the looser seccomp filter) available to the exploit child.
    lint {
        abortOnError = false
        checkReleaseBuilds = false
    }

    // the exploit and the module are only ever executed, never compressed in
    packaging {
        resources {
            excludes += setOf("META-INF/*.kotlin_module")
        }
    }
}

dependencies {
    // Shizuku is only used as a way to run the exploit in the shell domain:
    // untrusted_app has no perf_event permission, so the KASLR fit fails there.
    implementation("dev.rikka.shizuku:api:13.1.5")
    implementation("dev.rikka.shizuku:provider:13.1.5")
    implementation("dev.rikka.shizuku:aidl:13.1.5")

    // Root from the app's own uid, for the module actions when shell is not
    // on the KernelSU allowlist.
    implementation("com.github.topjohnwu.libsu:core:5.2.2")

    implementation(platform("androidx.compose:compose-bom:2026.02.01"))
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
}
