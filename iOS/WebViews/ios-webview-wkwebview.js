/*
 * Name: ios-webview-wkwebview.js
 * Category: iOS > WebView > WKWebView
 * Purpose: Inspect WKWebView instances and hook loadRequest / evaluateJavaScript
 * Author: Lehasa
 */

if (ObjC.available) {
    const STEALTH = false;
    function logInfo(msg) { if (!STEALTH) console.log(`[INFO] ${new Date().toISOString()} ${msg}`); }
    function logError(msg) { console.error(`[ERROR] ${new Date().toISOString()} ${msg}`); }

    function inspect_WKWebView(instance) {
        try {
            logInfo("[+] Inspecting WKWebView");
            logInfo("[+] URL: " + instance.URL().toString());
            logInfo("[+] JavaScript Enabled: " + instance.configuration().preferences().javaScriptEnabled());
            logInfo("[+] allowsContentJavaScript: " + instance.configuration().defaultWebpagePreferences().allowsContentJavaScript());
            logInfo("[+] allowFileAccessFromFileURLs: " + instance.configuration().preferences().valueForKey_('allowFileAccessFromFileURLs'));
            logInfo("[+] hasOnlySecureContent: " + instance.hasOnlySecureContent());
            logInfo("[+] allowUniversalAccessFromFileURLs: " + instance.configuration().valueForKey_('allowUniversalAccessFromFileURLs'));
        } catch (err) {
            logError("[!] Error inspecting WKWebView: " + err);
        }
    }

    const WKWebView = ObjC.classes.WKWebView;

    if (WKWebView) {
        // loadRequest hook
        Interceptor.attach(WKWebView['- loadRequest:'].implementation, {
            onEnter(args) {
                const request = new ObjC.Object(args[2]);
                const url = request.URL().absoluteString();
                logInfo(`[+] WKWebView loadRequest URL: ${url}`);
                logInfo(`[+] HTTP Method: ${request.HTTPMethod()}`);
                if (request.HTTPBody()) logInfo(`[+] HTTP Body: ${request.HTTPBody().toString()}`);
            }
        });

        // evaluateJavaScript hook
        Interceptor.attach(WKWebView['- evaluateJavaScript:completionHandler:'].implementation, {
            onEnter(args) {
                const jsCode = new ObjC.Object(args[2]);
                logInfo(`[+] JavaScript code to be executed: ${jsCode}`);
                this.completionHandler = args[3];
            },
            onLeave(retval) {
                if (this.completionHandler) {
                    const handler = new ObjC.Block(this.completionHandler);
                    const originalHandler = handler.implementation;
                    handler.implementation = function(result, error) {
                        if (!error.isNull()) logInfo(`[+] JavaScript result: ${result}`);
                        else logError(`[+] JavaScript execution error: ${error}`);
                        return originalHandler(result, error);
                    };
                }
            }
        });

        ObjC.choose(WKWebView, { onMatch: inspect_WKWebView, onComplete: () => logInfo('[+] Done WKWebView') });
    }
} else {
    console.error("[-] Objective-C runtime is not available.");
}
