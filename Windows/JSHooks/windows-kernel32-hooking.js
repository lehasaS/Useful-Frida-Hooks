var introLog = "[+] Starting Kernel32 Hooking Instrumentation";
console.log(introLog);
send({'content': introLog});

function safeReadUtf16(ptr){ try { return ptr.readUtf16String(); } catch(e){ return "<invalid>"; } }
function safeReadAnsi(ptr){ try { return ptr.readAnsiString(); } catch(e){ return "<invalid>"; } }
function safeHexDump(ptr, size=64){ try { return hexdump(ptr, {length:size, ansi:true}); } catch(e){ return "<unable to read memory>"; } }

const exports = {
    VirtualAlloc: Module.getExportByName('kernel32.dll', 'VirtualAlloc'),
    VirtualProtect: Module.getExportByName('kernel32.dll', 'VirtualProtect'),
    HeapAlloc: Module.getExportByName('kernel32.dll', 'HeapAlloc'),
    CryptUnprotectData: Module.getExportByName('crypt32.dll', 'CryptUnprotectData'),
    CreateFileA: Module.getExportByName('kernel32.dll', 'CreateFileA'),
    CreateFileW: Module.getExportByName('kernel32.dll', 'CreateFileW'),
    CreateMutexW: Module.getExportByName('kernel32.dll', 'CreateMutexW'),
    CreateMutexExA: Module.getExportByName('kernel32.dll', 'CreateMutexExA'),
    CreateMutexExW: Module.getExportByName('kernel32.dll', 'CreateMutexExW'),
    OpenMutexW: Module.getExportByName('kernel32.dll', 'OpenMutexW')
};

// --- File Operations ---
['CreateFileW', 'WriteFile', 'ReadFile', 'DeleteFileW'].forEach(fn => {
    Interceptor.attach(Module.getExportByName('kernel32.dll', fn), {
        onEnter(args){ console.log(`[File][${fn}] ${safeReadUtf16(args[0])}`); },
        onLeave(retval){ console.log(`[File][${fn}] Returned: ${retval}`); }
    });
});

// --- Registry Operations ---
['RegCreateKeyExW','RegSetValueExW','RegDeleteKeyW','RegCloseKey'].forEach(fn => {
    Interceptor.attach(Module.getExportByName('advapi32.dll', fn), {
        onEnter(args){ console.log(`[Registry][${fn}] Key: ${safeReadUtf16(args[1])}`); },
        onLeave(retval){ console.log(`[Registry][${fn}] Returned: ${retval}`); }
    });
});

// --- Network Activity ---
Interceptor.attach(Module.getExportByName('ws2_32.dll', 'connect'), {
    onEnter(args){
        const sockaddr = args[1];
        const ip = `${sockaddr.add(4).readU8()}.${sockaddr.add(5).readU8()}.${sockaddr.add(6).readU8()}.${sockaddr.add(7).readU8()}`;
        const port = sockaddr.add(2).readU16();
        console.log(`[Network][connect] ${ip}:${port}`);
    }
});

// --- DLL Loading ---
Interceptor.attach(Module.getExportByName('kernel32.dll', 'LoadLibraryW'), {
    onEnter(args){ console.log(`[DLL][LoadLibraryW] ${safeReadUtf16(args[0])}`); },
    onLeave(retval){ console.log(`[DLL][LoadLibraryW] Returned: ${retval}`); }
});

// --- Process Creation ---
Interceptor.attach(Module.getExportByName('kernel32.dll', 'CreateProcessW'), {
    onEnter(args){ console.log(`[Process][CreateProcessW] ${safeReadUtf16(args[0])}`); },
    onLeave(retval){ console.log(`[Process][CreateProcessW] Returned: ${retval}`); }
});

// --- VirtualAlloc ---
Interceptor.attach(exports.VirtualAlloc, {
    onEnter(args){ 
        console.log(`[VirtualAlloc] Size=${args[1].toInt32()} Protection=${args[3]}`); 
    },
    onLeave(retval){ 
        console.log(`[VirtualAlloc] Returned: ${retval}`);
        console.log("[VirtualAlloc] Hexdump (first 64 bytes): " + safeHexDump(retval));
    }
});

// --- VirtualProtect ---
Interceptor.attach(exports.VirtualProtect, {
    onEnter(args){
        console.log(`[VirtualProtect] Address=${args[0]} Size=${args[1].toInt32()} Protection=${args[2]}`);
        console.log("[VirtualProtect] Hexdump (first 64 bytes): " + safeHexDump(args[0]));
    }
});

// --- CryptUnprotectData ---
Interceptor.attach(exports.CryptUnprotectData, {
    onEnter(args){ console.log("[CryptUnprotectData] Called"); },
    onLeave(retval){ console.log("[CryptUnprotectData] Returned: " + retval); }
});

// --- HeapAlloc ---
Interceptor.attach(exports.HeapAlloc, {
    onLeave(retval){
        if(!retval.isNull()){
            try{
                let utf16 = Memory.readUtf16String(retval);
                console.log(`[HeapAlloc] UTF-16 Content: ${utf16}`);
            } catch(e){ /* safe fail */ }

            try{
                let raw = Memory.readByteArray(retval, 64);
                console.log("[HeapAlloc] Raw bytes hexdump:\n" + hexdump(raw, {length:64, ansi:true}));
            } catch(e){ /* safe fail */ }
        }
    }
});
// --- Mutex hooks ---
['CreateMutexW','CreateMutexExA','CreateMutexExW','OpenMutexW'].forEach(fn=>{
    const addr = exports[fn];
    if(addr){
        Interceptor.attach(addr,{
            onEnter(args){ console.log(`[Mutex][${fn}] Name: ${safeReadUtf16(args[0] || args[1] || args[2])}`); }
        });
    }
});
