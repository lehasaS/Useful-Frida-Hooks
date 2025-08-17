/*
 * Name: ios-webview-sfsafariviewcontroller.js
 * Category: iOS > WebView > SFSafariViewController
 * Purpose: Inspect SFSafariViewController instances and log URL, JavaScript, and secure content
 * Author: Lehasa
 */

if (ObjC.available) {
    const STEALTH = false;
    function logInfo(msg) { if (!STEALTH) console.log(`[INFO] ${new Date().toISOString()} ${msg}`); }
    function logError(msg) { console.error(`[ERROR] ${new Date().toISOString()} ${msg}`); }

    function inspect_SFSafariViewController(instance) {
        try {
            logInfo("[+] Inspecting SFSafariViewController");
            const url = instance.valueForKey_('initialURL');
            logInfo("[+] URL: " + (url ? url.toString() : 'No URL found'));
            const isSecure = url && url.toString().startsWith('https');
            logInfo("[+] Secure Content (HTTPS): " + (isSecure ? "Yes" : "No"));

            const config = instance.configuration();
            if (config) {
                logInfo("[+] JavaScript Enabled: " + (config.preferences().javaScriptEnabled() ? "Yes" : "No"));
                logInfo("[+] Enforces Secure Content: " + (!config.entirelyInsecureContentAllowed() ? "Yes" : "No"));
            }
        } catch (err) {
            logError("[!] Error inspecting SFSafariViewController: " + err);
        }
    }

    const SFSafariViewController = ObjC.classes.SFSafariViewController;
    if (SFSafariViewController) ObjC.choose(SFSafariViewController, { onMatch: inspect_SFSafariViewController, onComplete: () => logInfo('[+] Done SFSafariViewController') });

} else {
    console.error("[-] Objective-C runtime is not available.");
}
