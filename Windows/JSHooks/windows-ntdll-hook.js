/* 
==================================
   NTDLL: Heaven's Gate detection
==================================
*/

const STEALTH = false;

function logInfo(msg){ if(!STEALTH) console.log(`[INFO][Biometrics] ${new Date().toISOString()} ${msg}`); }
function logWarn(msg){ if(!STEALTH) console.warn(`[WARN][Biometrics] ${new Date().toISOString()} ${msg}`); }
function logError(msg){ if(!STEALTH) console.error(`[ERROR][Biometrics] ${new Date().toISOString()} ${msg}`); }


var modules = Process.enumerateModules();
var ntdll = modules.find(m => m.name.toLowerCase() === "ntdll.dll");

if (!ntdll) {
    logError("ntdll.dll not found!");
}

var ntdllBase = ntdll.base;
var ntdllOffset = ntdllBase.add(ntdll.size);
logInfo("Ntdll base: " + ntdllBase);
logInfo("Ntdll end: " + ntdllOffset);

// Track all threads
var threads = Process.enumerateThreads();


// Hook all running threads
threads.forEach(t => {
    Stalker.follow(t.id, {
        events: {
            call: false,
            ret: false,
            exec: false,
            block: false,
            compile: false
        },
        onReceive(events) {
            // Optional: Process captured events if needed
        },
        transform(iterator) {
            let instruction = iterator.next();
            do {
                if (instruction.mnemonic === "mov" && instruction.toString() === "mov r10, rcx") {
                    iterator.keep();
                    instruction = iterator.next();

                    if (instruction.mnemonic === "mov" && instruction.toString().split(',')[0] === "mov eax") {
                        var syscallAddress = instruction.address.toInt32();
                        if (syscallAddress < ntdllBase.toInt32() || syscallAddress > ntdllOffset.toInt32()) {
                            logInfo("Potentially malicious syscall detected at: " + instruction.address)
                            send("Potentially malicious syscall detected at: " + instruction.address);
                        }
                        
                    }
                }
                iterator.keep();
            } while ((instruction = iterator.next()) !== null);
        }
    });
});
