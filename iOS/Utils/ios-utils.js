/*
 * Name: ios-utils.js
 * Category: iOS Utils
 * Purpose: Common helper functions for Frida iOS hooks
 * Author: Lehasa
 */

const STEALTH = false;

function logInfo(msg) {
    if (!STEALTH) console.log(`[INFO] ${new Date().toISOString()} ${msg}`);
}

function logError(msg) {
    console.error(`[ERROR] ${new Date().toISOString()} ${msg}`);
}

function logNativeStackTrace(context) {
    try {
        console.log("[*] Native stack trace:\n" + Thread.backtrace(context, Backtracer.FUZZY)
            .map(DebugSymbol.fromAddress).join("\n"));
    } catch (err) {
        logError("Failed to log native stack: " + err.message);
    }
}

function getClassHandle(name) {
    return new Promise((resolve, reject) => {
        if (ObjC.available) {
            const classHandle = ObjC.classes[name];
            if (classHandle) resolve(classHandle);
            else reject(new Error("Class not found: " + name));
        } else {
            reject(new Error("Objective-C runtime not available."));
        }
    });
}

global.iosUtils = {
    logInfo,
    logError,
    logNativeStackTrace,
    getClassHandle
};
