/*
 * Name: android-webview-debug.js
 * Category: Android > WebView / Debugging
 * Purpose: Enable WebView debugging for all constructors
 * Author: Lehasa
 * Notes: Hooks all relevant constructors to call setWebContentsDebuggingEnabled(true)
 */

const STEALTH = false;

function logInfo(msg) {
    if (!STEALTH) console.log(`[INFO] ${new Date().toISOString()} ${msg}`);
}

Java.perform(() => {
    const WebView = Java.use("android.webkit.WebView");

    const constructors = [
        ["android.content.Context"],
        ["android.content.Context", "android.util.AttributeSet"],
        ["android.content.Context", "android.util.AttributeSet", "int"],
        ["android.content.Context", "android.util.AttributeSet", "int", "int"],
        ["android.content.Context", "android.util.AttributeSet", "int", "int", "java.util.Map", "boolean"],
        ["android.content.Context", "android.util.AttributeSet", "int", "java.util.Map", "boolean"]
    ];

    constructors.forEach(args => {
        WebView.$init.overload(...args).implementation = function() {
            const returnValue = this.$init.apply(this, arguments);
            this.setWebContentsDebuggingEnabled(true);
            logInfo("[+] Enabled WebView debugging");
            return returnValue;
        };
    });
});
