/*
 * Name: android-native-file-handling.js
 * Category: Android > Native / File APIs
 * Purpose: Instrument native file handling APIs to monitor fopen, open, stat, and access calls, including external storage usage
 * Author: Lehasa
 * Notes: Includes optional Java backtraces for context and timestamped logging with stealth mode support
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

// Optional: get Java backtrace
function backtrace() {
    try {
        const bt = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new());
        logInfo("Java backtrace:\n" + bt);
    } catch (err) {
        logError("Failed to get Java backtrace: " + err);
    }
}

// ==================== Hook libc File APIs ====================
const external_paths = ['/sdcard', '/storage/emulated'];

// Helper to read C strings safely
function readCStringSafe(ptrArg) {
    try {
        return ptrArg.readCString();
    } catch (err) {
        return "[INVALID POINTER]";
    }
}

// fopen
Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
    onEnter(args) {
        const path = readCStringSafe(args[0]);
        logInfo(`fopen called on: ${path}`);
        if (external_paths.some(p => path.startsWith(p))) {
            logWarning(`Opening a file from external storage: ${path}`);
            Java.performNow(backtrace);
        }
    }
});

// stat
Interceptor.attach(Module.findExportByName("libc.so", "stat"), {
    onEnter(args) {
        const path = readCStringSafe(args[0]);
        logInfo(`stat called on: ${path}`);
    }
});

// access
Interceptor.attach(Module.findExportByName("libc.so", "access"), {
    onEnter(args) {
        const path = readCStringSafe(args[0]);
        logInfo(`access called on: ${path}`);
    }
});

// Interceptor.attach(Module.findExportByName("libc.so", "access"), {
//     onEnter: function (args) {
//         var path = args[0].readCString();

//         if (path.includes("/sbin/su") || path.includes("/system/app/Superuser.apk")) {
//             console.log(`\naccess: ${path}`);
//             this.targetedAccess = true;
//         } else {
//             this.targetedAccess = false;
//         }
//     },
//     onLeave: function (retval) {
//         if (this.targetedAccess) {
//             retval.replace(-1);
//             console.log("Return Value: " + retval.toInt32());
//         }
//     }
// });


// open (covers Java APIs and external paths)
Interceptor.attach(Module.getExportByName(null, 'open'), {
    onEnter(args) {
        const path = readCStringSafe(ptr(args[0]));
        logInfo(`open called on: ${path}`);

        if (external_paths.some(p => path.startsWith(p))) {
            logWarning(`Opening a file from external storage: ${path}`);
            Java.performNow(backtrace);
        }
    }
});
