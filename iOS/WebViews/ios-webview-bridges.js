/*
 * Name: ios-webview-bridges.js
 * Category: iOS > WebView > JavaScript Bridges
 * Purpose: Hook known JS bridges and WKUserContentController usage
 * Author: Lehasa
 */

if (ObjC.available) {
    const STEALTH = false;
    function logInfo(msg) { if (!STEALTH) console.log(`[INFO] ${new Date().toISOString()} ${msg}`); }

    const bridgesToHook = [
        'JavascriptContextBridge',
        'JavascriptNotificationBridge',
        'JavascriptDataUpdateHandlerBridge',
        'JavascriptOTPBridge',
        'JavascriptDeepLinkingBridge',
        'PingSessionBridge',
        'JavascriptSelectContactBridge'
    ];

    bridgesToHook.forEach(bridgeName => {
        const BridgeClass = ObjC.classes[bridgeName];
        if (BridgeClass) {
            Interceptor.attach(BridgeClass['- postMessage:'].implementation, {
                onEnter(args) {
                    const message = new ObjC.Object(args[2]);
                    logInfo(`[+] ${bridgeName} postMessage called: ${message}`);
                }
            });
        }
    });

    const WKUserContentController = ObjC.classes.WKUserContentController;
    if (WKUserContentController) {
        Interceptor.attach(WKUserContentController['- addScriptMessageHandler:name:'].implementation, {
            onEnter(args) {
                const handler = new ObjC.Object(args[2]);
                const name = new ObjC.Object(args[3]);
                logInfo(`[+] WKUserContentController bridge: ${name} -> Handler: ${handler.$className}`);
            }
        });
    }

    const WebViewJavascriptBridge = ObjC.classes.WebViewJavascriptBridge;
    if (WebViewJavascriptBridge) {
        Interceptor.attach(WebViewJavascriptBridge['- registerHandler:handler:'].implementation, {
            onEnter(args) {
                logInfo("[+] WebViewJavascriptBridge registerHandler called");
            }
        });
    }
} else {
    console.error("[-] Objective-C runtime is not available.");
}
