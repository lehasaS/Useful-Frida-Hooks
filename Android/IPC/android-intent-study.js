/*
 * Name: android-intent-study.js
 * Category: Android > IPC
 * Purpose: Instrument common Intent flows and PendingIntent creation for analysis
 * Author: Lehasa
 * Notes: Includes implicit/explicit detection, extras dump, and mutability checks
 */

Java.perform(function () {
    const STEALTH = false;
    function logInfo(msg){ if(!STEALTH) console.log(`[INFO][IPC] ${new Date().toISOString()} ${msg}`); }
    function logWarn(msg){ if(!STEALTH) console.warn(`[WARN][IPC] ${new Date().toISOString()} ${msg}`); }
    function logError(msg){ if(!STEALTH) console.error(`[ERROR][IPC] ${new Date().toISOString()} ${msg}`); }

    logInfo("Initializing generalized Intent & PendingIntent hooks...");

    const classesToHook = [
        { className: "android.app.Activity", methodName: "startActivityForResult" },
        { className: "android.app.Activity", methodName: "onActivityResult" },
        { className: "android.app.Activity", methodName: "dispatchActivityResult" },
        { className: "androidx.fragment.app.FragmentActivity", methodName: "onActivityResult" },
        { className: "androidx.activity.ComponentActivity", methodName: "onActivityResult" },
        { className: "android.content.Context", methodName: "startActivity" },
        { className: "android.content.BroadcastReceiver", methodName: "onReceive" },
        { className: "android.app.PendingIntent", methodName: "getActivity" },
        { className: "android.app.PendingIntent", methodName: "getBroadcast" },
        { className: "android.app.PendingIntent", methodName: "getService" }
    ];

    function backtrace() {
        try {
            const Log = Java.use('android.util.Log');
            const Exception = Java.use('java.lang.Exception');
            const bt = Log.getStackTraceString(Exception.$new());
            logInfo("Backtrace:\n" + bt);
        } catch (e) {
            logError("Backtrace failed: " + e);
        }
    }

    function analyseIntent(source, intent) {
        logInfo(`\nAnalyzing Intent from ${source}`);
        try {
            if (!intent) {
                logWarn(`${source}: Null intent`);
                return;
            }

            const component = intent.getComponent();
            const pkg = intent.getPackage();
            if (component || pkg) {
                logWarn(`[-] Explicit Intent: ${component || pkg}`);
                return;
            } else {
                logInfo("[+] Implicit Intent detected");
            }

            logInfo(`[*] Action: ${intent.getAction() || "[None]"}`);
            logInfo(`[*] Data URI: ${intent.getDataString() || "[None]"}`);
            logInfo(`[*] Type: ${intent.getType() || "[None]"}`);

            try {
                const flags = intent.getFlags();
                logInfo(`[*] Flags: 0x${flags.toString(16)}`);
            } catch (_) {}

            const categories = intent.getCategories();
            if (categories) {
                try {
                    const it = categories.iterator();
                    while (it.hasNext()) logInfo(`[+] Category: ${it.next()}`);
                } catch (_) { logInfo("[-] Categories iteration failed"); }
            } else {
                logInfo("[-] No categories");
            }

            const extras = intent.getExtras();
            if (extras) {
                logInfo("[+] Extras:");
                try {
                    const keys = extras.keySet().toArray();
                    const Intent = Java.use("android.content.Intent");
                    for (let i = 0; i < keys.length; i++) {
                        const k = keys[i];
                        const v = extras.get(k);
                        if (v && v.getClass && v.getClass().getName() === "android.content.Intent") {
                            const nested = Java.cast(v, Intent);
                            logInfo(`[+] Nested Intent under key '${k}'`);
                            analyseIntent(`${source} -> Nested`, nested);
                        } else {
                            let vs = "[Unprintable]";
                            try { vs = String(v); } catch (_) {}
                            logInfo(`[+] ${k}: ${vs}`);
                        }
                    }
                } catch (e) {
                    logError("Failed reading extras: " + e);
                }
            } else {
                logInfo("[-] No extras");
            }

            try {
                const ActivityThread = Java.use("android.app.ActivityThread");
                const PackageManager = Java.use("android.content.pm.PackageManager");
                const ctx = ActivityThread.currentApplication().getApplicationContext();
                if (ctx) {
                    const pm = ctx.getPackageManager();
                    const list = pm.queryIntentActivities(intent, PackageManager.MATCH_ALL.value);
                    logInfo("[+] Potential handlers:");
                    for (let i = 0; i < list.size(); i++) {
                        logInfo("    " + list.get(i).toString());
                    }
                }
            } catch (e) {
                logInfo("[-] Could not resolve potential handlers: " + e);
            }

        } catch (e) {
            logError("Error analyzing Intent: " + e);
        }
    }

    function checkMutability(flags) {
        // PendingIntent.FLAG_IMMUTABLE = 0x40000000, FLAG_MUTABLE = 0x20000000 (values vary by API level)
        const FLAG_IMMUTABLE = 0x40000000;
        const FLAG_MUTABLE   = 0x20000000;

        if ((flags & FLAG_IMMUTABLE) !== 0) return `Immutable, Flag Value ${flags}`;
        if ((flags & FLAG_MUTABLE) !== 0)   return `Mutable, Flag Value ${flags}`;
        return `Default (Mutable pre-API 31), Flag Value ${flags}`;
        // For API 31+, default without explicit flag is immutable in some builders; always check docs/app behavior.
    }

    function analysePendingIntent(source, args) {
        logInfo(`\nAnalyzing PendingIntent from ${source}`);
        try {
            if (!args) { logInfo("[-] No args"); return; }

            // Heuristics to find Intent & flags in overload args
            let candidateIntent = null;
            let flags = 0;

            for (let i = 0; i < args.length; i++) {
                const a = args[i];
                try {
                    if (a && a.$className === "android.content.Intent") candidateIntent = a;
                } catch (_) {}
            }
            // flags are often the last int
            for (let i = args.length - 1; i >= 0; i--) {
                if (typeof args[i] === "number") { flags = args[i]; break; }
            }

            if (candidateIntent) {
                logInfo("[*] PendingIntent carries Intent: " + candidateIntent.toUri(0));
                analyseIntent(`${source}`, candidateIntent);
            } else {
                logInfo("[-] No Intent found among args");
            }

            logInfo("[*] Flags: " + flags);
            logInfo("[*] Mutability: " + checkMutability(flags));
        } catch (e) {
            logError("Error analyzing PendingIntent: " + e);
        }
    }

    // Hook dynamic methods
    classesToHook.forEach(function (hook) {
        try {
            const clazz = Java.use(hook.className);
            const method = clazz[hook.methodName];
            if (!method) {
                logWarn(`[-] Method not found: ${hook.className}.${hook.methodName}`);
                return;
            }

            method.overloads.forEach(function (over) {
                over.implementation = function () {
                    logInfo(`\nHooked ${hook.className}::${hook.methodName}`);
                    const args = arguments;

                    // Look for Intent arguments and analyze
                    for (let i = 0; i < args.length; i++) {
                        try {
                            if (args[i] && args[i].$className === "android.content.Intent") {
                                analyseIntent(`${hook.className}::${hook.methodName}`, args[i]);
                            }
                        } catch (_) {}
                    }

                    // Special analysis for PendingIntent creators
                    if (hook.className === "android.app.PendingIntent") {
                        analysePendingIntent(`${hook.className}::${hook.methodName}`, args);
                    }

                    return over.apply(this, args);
                };
            });

            logInfo(`Hooked ${hook.className}.${hook.methodName} (${method.overloads.length} overloads)`);
        } catch (e) {
            logError(`Error hooking ${hook.className}.${hook.methodName}: ${e}`);
        }
    });
});
