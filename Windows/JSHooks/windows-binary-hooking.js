/*
 * Author: Lehasa Seoe
 * Description: Frida hook for arbitrary function instrumentation in a given module.
 *              Demonstrates how to hook a function by address, log arguments, and return values.
 * Usage: Adjust `moduleName` and function offsets as needed for your target binary.
 */

// -------------------- Logging Helpers --------------------
const STEALTH = false;

function logInfo(msg){ if(!STEALTH) console.log(`[INFO][Biometrics] ${new Date().toISOString()} ${msg}`); }
function logWarn(msg){ if(!STEALTH) console.warn(`[WARN][Biometrics] ${new Date().toISOString()} ${msg}`); }
function logError(msg){ if(!STEALTH) console.error(`[ERROR][Biometrics] ${new Date().toISOString()} ${msg}`); }


// -------------------- Start Instrumentation --------------------
logInfo("Starting Instrumentation");

// -------------------- Target Module --------------------
var moduleName = "test.exe";   // Name of the target module
var baseAddr = Module.getBaseAddress(moduleName);

if (!baseAddr) {
    logError("Failed to find module base address for " + moduleName);
    return;
}

logInfo("Base address of " + moduleName + ": " + baseAddr);

// -------------------- Function Address Definitions --------------------
// Adjust the offsets based on reverse engineering results
var func1_addr = baseAddr.add(0x42482B);  // Address of fcn_0042482b

// -------------------- Function Hook --------------------
/*
 * Hook Description:
 *   This hook intercepts calls to fcn_0042482b in the target module.
 *   onEnter: Logs the incoming arguments. Modify logging as needed to read pointers, strings, or integers.
 *   onLeave: Logs the return value after the function executes.
 */
Interceptor.attach(func1_addr, {
    onEnter: function(args) {
        logInfo("Hooked fcn_0042482b @ " + func1_addr);
        logInfo("ECX (arg0): " + args[0].toInt32());  // Example integer argument
        logInfo("Arg1 (ptr): " + args[1]);            // Example pointer argument
    },
    onLeave: function(retval) {
        logInfo("Return Value: " + retval.toInt32()); // Example integer return value
    }
});
