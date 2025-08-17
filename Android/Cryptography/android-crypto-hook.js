/*
 * Name: okhttp-crypto-interceptor.js
 * Purpose: Intercept OkHttp requests and cryptographic operations in Android apps
 * Author: Lehasa
 * Tags: OkHttp, Cipher, Crypto, Frida, Hook
 */

const STEALTH = false;

function logInfo(msg) { if (!STEALTH) console.log(`[INFO] ${new Date().toISOString()} ${msg}`); }
function logError(msg) { console.error(`[ERROR] ${new Date().toISOString()} ${msg}`); }

const { getClassHandle } = global.utils; 

// -----------------------------
// Native Crypto Hook: CRYPTO_gcm128_encrypt_ctr32
// -----------------------------
const nativeName = "CRYPTO_gcm128_encrypt_ctr32";
const nativeAddr = Module.findExportByName(null, nativeName);

if (nativeAddr) {
    Interceptor.attach(nativeAddr, {
        onEnter(args) {
            console.log(`[*] Called ${nativeName}`);

            const len = parseInt(args[3].toInt32());
            const input = Memory.readByteArray(args[1], len);
            console.log("[*] Data to be encrypted:\n" + hexdump(input, { offset: 0, length: len, header: true, ansi: true }));

            // Optionally log IV (12 bytes, typical GCM)
            const iv = Memory.readByteArray(args[4], 12);
            console.log("[*] IV:\n" + hexdump(iv, { offset: 0, length: 12, header: true, ansi: true }));

            // Key pointer (do not read raw memory unless safe)
            console.log("[*] Key pointer:", args[0]);
        },
        onLeave(retval) {
            console.log(`[*] Finished ${nativeName} encryption.`);
        }
    });
} else {
    console.warn(`[!] Native export not found: ${nativeName}`);
}

Java.perform(function() {
    function printBacktrace() {
        const backtrace = Java.use('android.util.Log')
            .getStackTraceString(Java.use('java.lang.Exception').$new());
        logInfo(`Backtrace:\n${backtrace}`);
    }

    // ===================== Hook OkHttp Requests =====================
    getClassHandle("okhttp3.Request$Builder")
        .then(OkHttpRequestBuilder => {
            OkHttpRequestBuilder.build.implementation = function() {
                printBacktrace();

                const request = this.build();
                const url = request.url().toString();

                // Filter target URLs
                if (url.includes("/mobile/logs")) {
                    logInfo(`Intercepted OkHttp request to: ${url}`);
                    logInfo(`HTTP Method: ${request.method()}`);

                    const body = request.body();
                    if (body) {
                        const Buffer = Java.use('okio.Buffer');
                        const buffer = Buffer.$new();
                        body.writeTo(buffer);

                        let requestBody;
                        try {
                            requestBody = buffer.readUtf8();
                        } catch (e) {
                            requestBody = buffer.readByteArray();
                            logInfo(`Data (byte array): ${requestBody.toString('hex')}`);
                        }

                        logInfo(`Data before encryption: ${requestBody}`);
                    }
                }

                return request;
            };
        })
        .catch(error => logError(error));

    // ===================== Hook Cipher Operations =====================
    const ciphers = [
        { className: "javax.crypto.Cipher", overloads: [
            { method: "getInstance", args: ["java.lang.String"], log: "Cipher.getInstance called with transformation: " },
            { method: "init", args: ["int", "java.security.Key"], log: "Cipher.init called with mode and key: " },
            { method: "doFinal", args: ["[B"], log: "Cipher.doFinal called for data: " }
        ] },
        { className: "javax.crypto.SecretKeyFactory", overloads: [
            { method: "getInstance", args: ["java.lang.String"], log: "SecretKeyFactory.getInstance called with algorithm: " }
        ] },
        { className: "javax.crypto.KeyGenerator", overloads: [
            { method: "getInstance", args: ["java.lang.String"], log: "KeyGenerator.getInstance called with algorithm: " }
        ] },
        { className: "java.security.MessageDigest", overloads: [
            { method: "getInstance", args: ["java.lang.String"], log: "MessageDigest.getInstance called with algorithm: " }
        ] }
    ];

    ciphers.forEach(cipher => {
        getClassHandle(cipher.className)
            .then(clazz => {
                cipher.overloads.forEach(ov => {
                    clazz[ov.method].overload(...ov.args).implementation = function() {
                        logInfo(ov.log + Array.from(arguments).join(", "));
                        return this[ov.method].apply(this, arguments);
                    };
                });
            })
            .catch(error => logError(error));
    });

});

