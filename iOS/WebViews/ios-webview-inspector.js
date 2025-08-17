if (ObjC.available) {

    function printBacktrace() {
        console.log("Backtrace:\n" +
            Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join("\n") + "\n");
    }

    function iOSVersionFunc() {
        var processInfo = ObjC.classes.NSProcessInfo.processInfo();
        var versionString = processInfo.operatingSystemVersionString().toString();
        var versionTemp = versionString.split(' ');
        var version = versionTemp[1]; 
        return version;
    }

    var iOSVersionStr = iOSVersionFunc();
    var iOSVersionFloat = parseFloat(iOSVersionStr);
    console.log("iOS Version: " + iOSVersionStr);


    // Function to inspect SFSafariViewController and log additional properties
    function inspect_SFSafariViewController(SFSafariViewControllerInstance) {
        try {
            console.log('[+] Inspecting SFSafariViewController Instance');
            
            // Get the URL being displayed
            var url = SFSafariViewControllerInstance.valueForKey_('initialURL');
            console.log('[+] URL: ', url ? url.toString() : 'No URL found');
    
            // Check if the URL is loaded securely (HTTPS)
            var isSecureContent = url && url.toString().startsWith('https');
            console.log('[+] Secure Content (HTTPS): ', isSecureContent ? 'Yes' : 'No');
    
            // Additional Checks
            // Since SFSafariViewController is sandboxed, we can't modify much but can monitor its behavior.
    
            // Checking configuration for tracking and JavaScript
            var configuration = SFSafariViewControllerInstance.configuration();
            if (configuration) {
                // Check if JavaScript is enabled (it usually is, but useful to log)
                var javaScriptEnabled = configuration.preferences().javaScriptEnabled();
                console.log('[+] JavaScript Enabled: ', javaScriptEnabled ? 'Yes' : 'No');
    
                // Check whether secure content is enforced
                console.log('[+] Enforces Secure Content: ', configuration.entirelyInsecureContentAllowed() ? 'No' : 'Yes');
            }
            
        } catch (error) {
            console.error('[+] Error inspecting SFSafariViewController: ', error);
        }
    }
    

    // Function to inspect UIWebView and log additional properties
    // This webview type is deprecated starting on iOS 12 
    function inspect_UIWebView(WebViewInstance) {
        console.log('[+] Inspecting UIWebView Instance [+]');
        try {
            console.log('[+] Inspecting UIWebView Instance [+]');
            
            // Print the current URL
            var request = WebViewInstance.request();
            if (request) {
                var url = request.URL();
                console.log('[+] URL: ', url ? url.toString() : 'No URL found');
            }
    
            // Check JavaScript enabled status
            var javaScriptEnabled = WebViewInstance.stringByEvaluatingJavaScriptFromString_('navigator.userAgent');
            console.log('[+] JavaScript Enabled: ', javaScriptEnabled ? 'Yes' : 'No');
    
            // Check if it allows inline media playback (could affect media content security)
            var allowsInlineMediaPlayback = WebViewInstance.allowsInlineMediaPlayback();
            console.log('[+] Allows Inline Media Playback: ', allowsInlineMediaPlayback ? 'Yes' : 'No');
    
            // Check if AirPlay is allowed (could leak media content)
            var allowsAirPlay = WebViewInstance.mediaPlaybackAllowsAirPlay();
            console.log('[+] Allows AirPlay: ', allowsAirPlay ? 'Yes' : 'No');
    
            // Check if web content is loaded securely (HTTPS)
            var isSecureContent = url && url.toString().startsWith('https');
            console.log('[+] Secure Content: ', isSecureContent ? 'Yes' : 'No');
    
            // Inspect whether it allows access to local files
            var allowsFileAccess = WebViewInstance.valueForKey_('allowFileAccessFromFileURLs').toString();
            console.log('[+] Allow File Access From File URLs: ', allowsFileAccess);
    
            // Universal access from file URLs (security risk)
            var allowsUniversalAccessFromFileURLs = WebViewInstance.valueForKey_('allowUniversalAccessFromFileURLs').toString();
            console.log('[+] Allow Universal Access From File URLs: ', allowsUniversalAccessFromFileURLs);
        } catch (error) {
            console.error('[+] Error inspecting UIWebView: ', error);
        }
    }
    

    // Function to inspect WKWebView and log additional properties
    function inspect_WKWebView(WebViewInstance) {
        console.log('[+] URL: ', WebViewInstance.URL().toString());
        console.log('[+] javaScriptEnabled: ', WebViewInstance.configuration().preferences().javaScriptEnabled());
        console.log('[+] allowsContentJavaScript: ', WebViewInstance.configuration().defaultWebpagePreferences().allowsContentJavaScript());
        console.log('[+] allowFileAccessFromFileURLs: ', WebViewInstance.configuration().preferences().valueForKey_('allowFileAccessFromFileURLs').toString());
        console.log('[+] hasOnlySecureContent: ', WebViewInstance.hasOnlySecureContent().toString());
        console.log('[+] allowUniversalAccessFromFileURLs: ', WebViewInstance.configuration().valueForKey_('allowUniversalAccessFromFileURLs').toString());
    }


    // Hooking WKUserContentController's `addScriptMessageHandler:name:`
    var WKUserContentController = ObjC.classes.WKUserContentController;
    if (WKUserContentController) {
        Interceptor.attach(WKUserContentController['- addScriptMessageHandler:name:'].implementation, {
            onEnter: function (args) {
                console.log("\n[+] Check if application uses JavaScript Bridge (WKUserContentController)");
                console.log(`[+] Class: 'WKUserContentController' Method: '- addScriptMessageHandler:name:' Called`);
                
                var handler = new ObjC.Object(args[2]); // Message handler
                var name = new ObjC.Object(args[3]); // Name of the bridge
                
                console.log("[+] Bridge Name: " + name + " -> Handler: " + handler.$className);
            }
        });
    }

    var WKWebView = ObjC.classes.WKWebView;
    if (WKWebView) {
        // Hook the 'loadRequest:' method to capture the URL loading into the WKWebView
        Interceptor.attach(WKWebView['- loadRequest:'].implementation, {
            onEnter: function (args) {
                var request = new ObjC.Object(args[2]); // NSURLRequest
                var url = request.URL().absoluteString();
                console.log('[+] WKWebView loadRequest URL:', url);
            }
        });
    }

    // var NSString = ObjC.classes.NSString;
    // Interceptor.attach(NSString['- stringByAppendingString:'].implementation, {
    //     onEnter: function(args) {
    //         console.log('Concatenating string: ', ObjC.Object(args[2]).toString());
    //     }
    // });

    var WKWebView = ObjC.classes.WKWebView;
    if (WKWebView) {
        // Hook the 'evaluateJavaScript:completionHandler:' method
        Interceptor.attach(WKWebView['- evaluateJavaScript:completionHandler:'].implementation, {
            onEnter: function (args) {
                var jsCode = new ObjC.Object(args[2]); // The JavaScript code being executed
                console.log('[+] JavaScript code to be executed: ' + jsCode.toString());

                // Save the completion handler for later
                this.completionHandler = args[3];
            },
            onLeave: function (retval) {
                if (this.completionHandler) {
                    // Hook the completion handler to capture the result of the JavaScript execution
                    var handler = new ObjC.Block(this.completionHandler);
                    var originalHandler = handler.implementation;
                    handler.implementation = function (result, error) {
                        if (!error.isNull()) {
                            console.log('[+] JavaScript execution result: ' + result.toString());
                        } else {
                            console.log('[+] JavaScript execution error: ' + error);
                        }
                        // Call the original completion handler
                        return originalHandler(result, error);
                    };
                }
            }
        });
    } else {
        console.log('[-] WKWebView class not found.');
    }

    // Hooking specific bridges to log parameters
    const bridgesToHook = [
        'JavascriptContextBridge',
        'JavascriptNotificationBridge',
        'JavascriptDataUpdateHandlerBridge',
        'JavascriptOTPBridge',
        'JavascriptDeepLinkingBridge',
        'PingSessionBridge',
        'JavascriptSelectContactBridge'
    ];
    bridgesToHook.forEach(function(bridgeName) {
        var BridgeClass = ObjC.classes[bridgeName];
        if (BridgeClass) {
            Interceptor.attach(BridgeClass['- postMessage:'].implementation, {
                onEnter: function (args) {
                    var message = new ObjC.Object(args[2]); // The message being sent
                    console.log("\n[+] Hooking " + bridgeName + " [+]");
                    console.log("postMessage called with message: " + message.toString());
                }
            });
        }
    });

    // Hooking WebViewJavascriptBridge
    var WebViewJavascriptBridge = ObjC.classes.WebViewJavascriptBridge;
    if (WebViewJavascriptBridge) {
        Interceptor.attach(WebViewJavascriptBridge['- registerHandler:handler:'].implementation, {
            onEnter: function (args) {
                console.log("[+] Check if application uses JavaScript Bridge (WebViewJavascriptBridge)");
                console.log(`\nClass: 'WebViewJavascriptBridge' Method: '- registerHandler:handler:' Called`);
                var name = new ObjC.Object(args[2].toString());
                console.log("Handler Name: " + name);
            }
        });
    }

    var WKWebView = ObjC.classes.WKWebView;
    if (WKWebView) {
        Interceptor.attach(WKWebView['- loadRequest:'].implementation, {
            onEnter: function (args) {
                var request = new ObjC.Object(args[2]);
                var url = request.URL().absoluteString();
                console.log('[+] WKWebView loadRequest URL:', url);

                console.log('[+] HTTP Method: ' + request.HTTPMethod());
                if (request.HTTPBody()) {
                    console.log('[+] HTTP Body: ' + request.HTTPBody().toString());
                }
            },
            onLeave: function (retval) {
               console.log(retval);
            }
        });
    } else {
        console.log('[-] WKWebView class not found.');
    }

    // Finding and inspecting SFSafariViewController instances
    var SFSafariViewController = ObjC.classes.SFSafariViewController;
    if (SFSafariViewController) {
      console.log(`[+] Found SFSafariViewController`);
      ObjC.choose(SFSafariViewController, {
        onMatch: function (WebViewInstance) {
          console.log('onMatch: ', WebViewInstance);
          inspect_SFSafariViewController(WebViewInstance);
        },
        onComplete: function () {
          console.log('[+] done for SFSafariViewController!\n');
        }
      });
    }

    // Finding and inspecting UIWebView instances
    var UIWebView = ObjC.classes.UIWebView;
    if (UIWebView) {
        console.log('[+] Found UIWebView');
        ObjC.choose(UIWebView, {
            onMatch: function (WebViewInstance) {
                console.log('onMatch: ', WebViewInstance);
                inspect_UIWebView(WebViewInstance);
            },
            onComplete: function () {
                console.log('[+] Done for UIWebView\n');
            }
        });
    }

    // Finding and inspecting WKWebView instances
    var WKWebView = ObjC.classes.WKWebView;
    if (WKWebView) {
        console.log('[+] Found WKWebView');
        ObjC.choose(WKWebView, {
            onMatch: function (WebViewInstance) {
                console.log('onMatch: ', WebViewInstance);
                inspect_WKWebView(WebViewInstance);
            },
            onComplete: function () {
                console.log('[+] Done for WKWebView\n');
            }
        });
    }

}
