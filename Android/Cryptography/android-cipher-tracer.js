/*
 * Name: android-cipher-tracer.js
 * Category: Android > Cryptography
 * Purpose: Trace Cipher usage (encryption/decryption) in Android apps
 * Author: Lehasa
 * Tags: Cipher, Crypto, Frida, Hook
 */

const STEALTH = false;
function logInfo(msg){ if(!STEALTH) console.log(`[INFO][CipherTracer] ${new Date().toISOString()} ${msg}`); }
function logWarn(msg){ if(!STEALTH) console.warn(`[WARN][CipherTracer] ${new Date().toISOString()} ${msg}`); }
function logError(msg){ if(!STEALTH) console.error(`[ERROR][CipherTracer] ${new Date().toISOString()} ${msg}`); }

Java.perform(function() {
    logInfo("Initializing Cipher hooks...");

    const Cipher = Java.use('javax.crypto.Cipher');

    Cipher.init.overloads.forEach(overload => {
        overload.implementation = function(opmode, key, params){
            logInfo(`[Cipher init] Mode: ${opmode}, Key: ${key ? key.toString() : 'null'}, Params: ${params || 'null'}`);
            return overload.apply(this, arguments);
        };
    });

    Cipher.doFinal.overloads.forEach(overload => {
        overload.implementation = function(input){
            logInfo(`[Cipher doFinal] Input length: ${input ? input.length : 'null'}`);
            const result = overload.apply(this, arguments);
            logInfo(`[Cipher doFinal] Output length: ${result ? result.length : 'null'}`);
            return result;
        };
    });

    logInfo("Cipher hooks successfully attached.");
});
