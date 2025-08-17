/*
 * Name: android-load-native-libraries.js
 * Purpose: Intercept calls to load library
 * Author: Lehasa
 * Tags: OkHttp, Cipher, Crypto, Frida, Hook
 */
const STEALTH = false;

function logInfo(msg) { 
    if (!STEALTH) console.log(`[INFO] ${new Date().toISOString()} ${msg}`); 
}

function logError(msg) { 
    console.error(`[ERROR] ${new Date().toISOString()} ${msg}`); 
}

// ==================== Hook Native Library Loads ====================
Java.perform(() => {
    const { backtrace } = global.utils;

    const ClassLoader = Java.use("java.lang.ClassLoader");
    const PathClassLoader = Java.use("dalvik.system.PathClassLoader");

    // Get the current system class loader
    const currentClassLoader = ClassLoader.getSystemClassLoader();
    logInfo("Current ClassLoader: " + currentClassLoader);

    // Hook PathClassLoader.loadLibrary to log native library loads
    PathClassLoader.loadLibrary.implementation = function (name) {
        logInfo("Loading native library: " + name);
        backtrace(); // optional: show where loadLibrary was called
        return this.loadLibrary(name);
    };

    // Inspect currently loaded DEX elements
    try {
        const dexElementsField = PathClassLoader.class.getDeclaredField("dexElements");
        dexElementsField.setAccessible(true);
        const dexElements = dexElementsField.get(currentClassLoader);
        logInfo("Currently loaded DEX elements: " + dexElements);
    } catch (err) {
        logError("Error accessing dexElements: " + err);
    }
});