const ObjC = globalThis.ObjC;

if (ObjC.avilable){
    // Basic Setup
    console.log("Starting extensive Frida logging...");

    // Hook UIApplicationDelegate to monitor app launch and lifecycle
    const UIApplicationDelegate = ObjC.classes.UIApplicationDelegate;
    if (UIApplicationDelegate) {
        console.log("[UIApplicationDelegate] Hooking application lifecycle...");

        UIApplicationDelegate["- application:didFinishLaunchingWithOptions:"].implementation = function (application, options) {
            console.log("[UIApplicationDelegate] didFinishLaunchingWithOptions triggered");
            return this["- application:didFinishLaunchingWithOptions:"](application, options);
        };

        UIApplicationDelegate["- applicationDidBecomeActive:"].implementation = function (application) {
            console.log("[UIApplicationDelegate] applicationDidBecomeActive triggered");
            return this["- applicationDidBecomeActive:"](application);
        };

        UIApplicationDelegate["- applicationDidEnterBackground:"].implementation = function (application) {
            console.log("[UIApplicationDelegate] applicationDidEnterBackground triggered");
            return this["- applicationDidEnterBackground:"](application);
        };
    }

    // Hook UIViewController methods to observe view loading and appearances
    const UIViewController = ObjC.classes.UIViewController;
    UIViewController["- viewDidLoad"].implementation = function () {
        console.log("[UIViewController] viewDidLoad for:", this.$className);
        return this["- viewDidLoad"]();
    };

    UIViewController["- viewDidAppear:"].implementation = function (animated) {
        console.log("[UIViewController] viewDidAppear for:", this.$className);
        return this["- viewDidAppear:"](animated);
    };

    // Catch all exceptions globally
    Interceptor.attach(ObjC.classes.NSException["- initWithName:reason:userInfo:"].implementation, {
        onEnter: function (args) {
            console.log("[NSException] Caught Exception");
            console.log("Name:", ObjC.Object(args[2]).toString());
            console.log("Reason:", ObjC.Object(args[3]).toString());
        }
    });

    // Memory management debugging (especially useful if memory access issues might cause crashes)
    const malloc = Module.findExportByName("libsystem_malloc.dylib", "malloc");
    Interceptor.attach(malloc, {
        onEnter: function (args) {
            console.log("[Memory] Malloc called with size:", args[0].toInt32());
        },
    });

    const free = Module.findExportByName("libsystem_malloc.dylib", "free");
    Interceptor.attach(free, {
        onEnter: function (args) {
            console.log("[Memory] Free called with ptr:", args[0]);
        },
    });

    // Network logging: Capture HTTP request details
    const NSURLSession = ObjC.classes.NSURLSession;
    NSURLSession["- dataTaskWithRequest:completionHandler:"].implementation = function (request, handler) {
        console.log("[NSURLSession] HTTP Request:", ObjC.Object(request).URL().absoluteString());
        return this["- dataTaskWithRequest:completionHandler:"](request, handler);
    };

    // Log Keychain Access (commonly involved in app crashes related to security)
    const SecItemAdd = Module.findExportByName("Security", "SecItemAdd");
    const SecItemUpdate = Module.findExportByName("Security", "SecItemUpdate");
    const SecItemDelete = Module.findExportByName("Security", "SecItemDelete");

    function keychainHandler(name) {
        return function (args) {
            console.log(`[Keychain] ${name} called`);
            console.log("Attributes:", ObjC.Object(args[0]).toString());
        };
    }

    Interceptor.attach(SecItemAdd, { onEnter: keychainHandler("SecItemAdd") });
    Interceptor.attach(SecItemUpdate, { onEnter: keychainHandler("SecItemUpdate") });
    Interceptor.attach(SecItemDelete, { onEnter: keychainHandler("SecItemDelete") });

    // Log details of certificate validation to identify SSL-related issues
    const SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
    if (SecTrustEvaluate) {
        Interceptor.attach(SecTrustEvaluate, {
            onEnter: function (args) {
                console.log("[Security] SecTrustEvaluate called");
                const trust = new ObjC.Object(args[0]);
                console.log("[Security] Trust Object:", trust);
            },
            onLeave: function (retval) {
                console.log("[Security] SecTrustEvaluate return value:", retval);
            }
        });
    }

    // Exception handling for Objective-C classes to catch crashes
    const objcMsgSend = Module.findExportByName("libobjc.A.dylib", "objc_msgSend");
    Interceptor.attach(objcMsgSend, {
        onEnter: function (args) {
            try {
                const receiver = new ObjC.Object(args[0]);
                const selector = ObjC.selectorAsString(args[1]);
                console.log(`[objc_msgSend] ${receiver.$className} -> ${selector}`);
            } catch (e) {
                console.log("[objc_msgSend] Exception while processing message send:", e);
            }
        },
    });

    console.log("Frida extensive logging setup complete.");
} else {
    console.log("Objective-C runtime is not available.");
}
