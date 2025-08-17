/*
 * Name: android-webview-hooks.js
 * Category: Android > WebView / JS Bridges
 * Purpose: Instrument WebView instances, JS interfaces, URL loads, and evaluateJavascript calls
 * Author: Lehasa
 * Notes: Includes JavaScript interface enumeration, and optional stealth mode
 */

// ==================== Metadata & Logging ====================
const STEALTH = false;

function logInfo(msg) {
    if (!STEALTH) console.log(`[INFO] ${new Date().toISOString()} ${msg}`);
}

function logWarning(msg) {
    if (!STEALTH) console.warn(`[WARNING] ${new Date().toISOString()} ${msg}`);
}

function logError(msg) {
    console.error(`[ERROR] ${new Date().toISOString()} ${msg}`);
}

function backtrace() {
    try {
        const bt = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new());
        logInfo("Java backtrace:\n" + bt);
    } catch (err) {
        logError("Failed to get Java backtrace: " + err);
    }
}

// ==================== WebView Instance Enumeration ====================
Java.perform(() => {
    Java.choose("android.webkit.WebView", {
        onMatch(instance) {
            Java.scheduleOnMainThread(() => {
                logInfo(`[+] Found WebView instance: ${instance}`);
                const settings = instance.getSettings();
                logInfo(`[*] JavaScript Enabled: ${settings.getJavaScriptEnabled()}`);
                logInfo(`[*] AllowUniversalAccessFromFileURLs: ${settings.getAllowUniversalAccessFromFileURLs()}`);
                logInfo(`[*] AllowFileAccessFromFileURLs: ${settings.getAllowFileAccessFromFileURLs()}`);
                logInfo(`[*] AllowFileAccess: ${settings.getAllowFileAccess()}`);
            });
        },
        onComplete() {
            logInfo("Finished enumerating WebView instances!");
        }
    });
});

// ==================== JS Interface Hooks ====================
Java.perform(() => {
    const WebView = Java.use("android.webkit.WebView");

    WebView.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String').implementation = function(obj, interfaceName) {
        logInfo(`[+] JavaScript interface added: ${interfaceName} -> Object: ${obj}`);
        return this.addJavascriptInterface(obj, interfaceName);
    };

    WebView.evaluateJavascript.overload('java.lang.String', 'android.webkit.ValueCallback').implementation = function(script, callback) {
        logInfo(`[+] evaluateJavascript called with script: ${script}`);
        return this.evaluateJavascript(script, callback);
    };

    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        logInfo(`[+] WebView loadUrl called: ${url}`);
        return this.loadUrl(url);
    };
});
