/*
 * Name: android-enumerate-classes-and-methods.js
 * Category: Android > Classes
 * Purpose: Enumerate loaded classes matching a keyword and list their declared methods
 * Author: Lehasa
 * Created: YYYY-MM-DD
 * Tags: Classes, Enumeration, Recon
 */

const STEALTH = false;
function logInfo(msg){ if(!STEALTH) console.log(`[INFO][Classes] ${new Date().toISOString()} ${msg}`); }
function logError(msg){ if(!STEALTH) console.error(`[ERROR][Classes] ${new Date().toISOString()} ${msg}`); }

Java.perform(function () {
    const pattern = "Class Key Word";

    try {
        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                if(!className.includes(pattern)) return;
                try {
                    const clazz = Java.use(className);
                    logInfo(`Hooking class: ${className}`);
                    const methods = clazz.class.getDeclaredMethods();
                    methods.forEach(method => {
                        try {
                            const params = method.getParameterTypes().map(p => p.getName());
                            logInfo(`[+] ${method.getName()}(${params.join(', ')})`);
                        } catch(e){ logError("Failed processing method: " + e); }
                    });
                } catch(e){ logError("Failed to hook class: " + className + " Error: " + e); }
            },
            onComplete: function(){ logInfo("Class enumeration completed"); }
        });
    } catch(e){ logError("Enumeration failed: " + e); }
});
