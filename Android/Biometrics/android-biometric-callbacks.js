/*
 * Name: android-biometric-callbacks.js
 * Category: Android > Biometrics
 * Purpose: Observe BiometricPrompt callbacks and CryptoObject interactions
 * Author: Lehasa
 * Tags: Biometric, Crypto, Hook
 */

const STEALTH = false;

function logInfo(msg){ if(!STEALTH) console.log(`[INFO][Biometrics] ${new Date().toISOString()} ${msg}`); }
function logWarn(msg){ if(!STEALTH) console.warn(`[WARN][Biometrics] ${new Date().toISOString()} ${msg}`); }
function logError(msg){ if(!STEALTH) console.error(`[ERROR][Biometrics] ${new Date().toISOString()} ${msg}`); }

Java.perform(function () {
    var isRunning = false;
    try {
        const BiometricAuthCallback = Java.use('PLACEHOLDER_CALLBACK'); // Replace with actual callback
        BiometricAuthCallback.onAuthenticationSucceeded.implementation = function (authResult) {
            logInfo("Entered onAuthenticationSucceeded");
            isRunning = true;
            const ret = this.onAuthenticationSucceeded(authResult);
            isRunning = false;
            logInfo("Exiting onAuthenticationSucceeded");
            return ret;
        };
        logInfo("BiometricAuthCallback hooked");
    } catch (err) {
        logError("Failed to hook BiometricAuthCallback: " + err);
    }

    try {
        const CryptoObject = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
        CryptoObject.getSignature.implementation = function () {
            if (isRunning) {
                logWarn("getSignature called while isRunning=true, returning null");
                return null;
            }
            const sig = this.getSignature();
            logInfo("getSignature called, returning original value");
            return sig;
        };
        logInfo("CryptoObject.getSignature hooked");
    } catch (err) {
        logError("Failed to hook CryptoObject.getSignature: " + err);
    }
});
