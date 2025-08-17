/*
 * Name: android-keystore-tracer.js
 * Category: Android > Cryptography
 * Purpose: Trace Android Keystore usage
 * Author: Lehasa
 * Created: YYYY-MM-DD
 * Tags: Keystore, Crypto, Android, Hook, Frida
 */

const STEALTH = false;
function logInfo(msg){ if(!STEALTH) console.log(`[INFO][KeystoreTracer] ${new Date().toISOString()} ${msg}`); }
function logWarn(msg){ if(!STEALTH) console.warn(`[WARN][KeystoreTracer] ${new Date().toISOString()} ${msg}`); }
function logError(msg){ if(!STEALTH) console.error(`[ERROR][KeystoreTracer] ${new Date().toISOString()} ${msg}`); }

Java.perform(function() {
    logInfo("Attaching Android Keystore hooks...");

    try {
        const KeyStore = Java.use('java.security.KeyStore');
        KeyStore.getInstance.overloads.forEach(ov => {
            ov.implementation = function(type) {
                logInfo(`[KeyStore] getInstance called with type: ${type}`);
                return ov.apply(this, arguments);
            };
        });

        const KeyGenerator = Java.use('javax.crypto.KeyGenerator');
        KeyGenerator.getInstance.overloads.forEach(ov => {
            ov.implementation = function(algo) {
                logInfo(`[KeyGenerator] getInstance called with algorithm: ${algo}`);
                return ov.apply(this, arguments);
            };
        });

        logInfo("Android Keystore hooks successfully attached.");
    } catch(e) {
        logError("Error attaching Keystore hooks: " + e);
    }
});
