import java.io.FileInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val localProperties = Properties().apply {
    val f = rootProject.file("local.properties")
    if (f.exists()) load(FileInputStream(f))
}
val cloudProjectNumber: String = localProperties.getProperty("integrity.cloudProjectNumber") ?: "0"

android {
    namespace = "com.onuroktayr.integrity"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.onuroktayr.integrity"
        minSdk = 24
        targetSdk = 36
        versionCode = 14
        versionName = "1.4"

        buildConfigField("long", "CLOUD_PROJECT_NUMBER", "${cloudProjectNumber}L")
    }

    signingConfigs {
        create("release") {
            val storeFileName = localProperties.getProperty("release.storeFile")
            if (storeFileName != null) {
                storeFile = rootProject.file("app/$storeFileName")
                storePassword = localProperties.getProperty("release.storePassword")
                keyAlias = localProperties.getProperty("release.keyAlias")
                keyPassword = localProperties.getProperty("release.keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        buildConfig = true
    }
}

dependencies {
    implementation("com.google.android.play:integrity:1.6.0")

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("androidx.cardview:cardview:1.0.0")

    // ASN.1 (DER) decoding of the Android Key Attestation certificate extension
    // (OID 1.3.6.1.4.1.11129.2.1.17). Used only for structural parsing - never
    // installed as a JCA security provider, so it does not conflict with the
    // platform's own (differently-packaged) BouncyCastle-derived provider.
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
}
