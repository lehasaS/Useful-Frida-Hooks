/*
 * Name: ios-webview-uiwebview.js
 * Category: iOS > WebView > UIWebView
 * Purpose: Inspect existing UIWebView instances and log URL, JS, media, and file access
 * Author: Lehasa
 */

if (ObjC.available) {
    const STEALTH = false;
    function logInfo(msg) { if (!STEALTH) console.log(`[INFO] ${new Date().toISOString()} ${msg}`); }
    function logError(msg) { console.error(`[ERROR] ${new Date().toISOString()} ${msg}`); }

    function inspect_UIWebView(instance) {
        try {
            logInfo("[+] Inspecting UIWebView");
            const request = instance.request();
            const url = request ? request.URL() : null;
            logInfo("[+] URL: " + (url ? url.toString() : 'No URL found'));
            const jsEnabled = instance.stringByEvaluatingJavaScriptFromString_('navigator.userAgent');
            logInfo("[+] JavaScript Enabled: " + (jsEnabled ? "Yes" : "No"));
            logInfo("[+] Allows Inline Media Playback: " + (instance.allowsInlineMediaPlayback() ? "Yes" : "No"));
            logInfo("[+] Allows AirPlay: " + (instance.mediaPlaybackAllowsAirPlay() ? "Yes" : "No"));
            logInfo("[+] Secure Content (HTTPS): " + (url && url.toString().startsWith('https') ? "Yes" : "No"));
            logInfo("[+] Allow File Access From File URLs: " + instance.valueForKey_('allowFileAccessFromFileURLs'));
            logInfo("[+] Allow Universal Access From File URLs: " + instance.valueForKey_('allowUniversalAccessFromFileURLs'));
        } catch (err) {
            logError("[!] Error inspecting UIWebView: " + err);
        }
    }

    const UIWebView = ObjC.classes.UIWebView;
    if (UIWebView) ObjC.choose(UIWebView, { onMatch: inspect_UIWebView, onComplete: () => logInfo('[+] Done UIWebView') });

} else {
    console.error("[-] Objective-C runtime is not available.");
}
