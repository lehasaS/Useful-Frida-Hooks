import frida, csv, threading
from frida_tools.application import Reactor

with open('result.csv','w',newline='') as f: csv.writer(f).writerow(["UTF-16"])

script_source = """
function logEvent(type,msg){ send({type:type,content:msg}); }
function safeReadUtf16(ptr){ try{ return ptr.readUtf16String(); }catch(e){ return "<invalid>"; } }

['CreateFileW','CreateFileA','WriteFile','ReadFile','DeleteFileW'].forEach(fn=>{
    Interceptor.attach(Module.getExportByName('kernel32.dll', fn), {
        onEnter(args){ logEvent('File', `[${fn}] ${safeReadUtf16(args[0])}`); },
        onLeave(retval){ logEvent('File', `[${fn}] Returned: ${retval}`); }
    });
});

['RegCreateKeyExW','RegSetValueExW','RegDeleteKeyW','RegCloseKey'].forEach(fn=>{
    Interceptor.attach(Module.getExportByName('advapi32.dll', fn), {
        onEnter(args){ logEvent('Registry', `[${fn}] ${safeReadUtf16(args[1])}`); },
        onLeave(retval){ logEvent('Registry', `[${fn}] Returned: ${retval}`); }
    });
});

Interceptor.attach(Module.getExportByName('ws2_32.dll','connect'),{
    onEnter(args){
        const s = args[1]; const ip = `${s.add(4).readU8()}.${s.add(5).readU8()}.${s.add(6).readU8()}.${s.add(7).readU8()}`;
        const port = s.add(2).readU16(); logEvent('Network', `[connect] ${ip}:${port}`);
    }
});

Interceptor.attach(Module.getExportByName('kernel32.dll','LoadLibraryW'),{
    onEnter(args){ logEvent('DLL', `[LoadLibraryW] ${safeReadUtf16(args[0])}`); },
    onLeave(retval){ logEvent('DLL', `[LoadLibraryW] Returned: ${retval}`); }
});

Interceptor.attach(Module.getExportByName('kernel32.dll','CreateProcessW'),{
    onEnter(args){ logEvent('Process', `[CreateProcessW] ${safeReadUtf16(args[0])}`); },
    onLeave(retval){ logEvent('Process', `[CreateProcessW] Returned: ${retval}`); }
});
"""

# Python Frida app structure
class Application:
    def __init__(self):
        self._stop = threading.Event()
        self._reactor = Reactor(run_until_return=lambda r:self._stop.wait())
        self._device = frida.get_local_device()
        self._sessions = set()
        self.check_new_process()

    def check_new_process(self):
        for p in self._device.enumerate_processes():
            if p.name.lower() in ['notely-setup-x64.msi','msiexec.exe','rundll32.exe'] and p.pid not in self._sessions:
                self.attach_process(p.pid)
        threading.Timer(1,self.check_new_process).start()

    def attach_process(self,pid):
        try:
            sess = self._device.attach(pid)
            sess.on("detached", lambda reason: self._sessions.discard(pid))
            scr = sess.create_script(script_source)
            scr.on('message', self.on_message)
            scr.load()
            self._sessions.add(pid)
        except Exception as e: print(f"Failed to attach {pid}: {e}")

    def on_message(self,message,data):
        if 'payload' in message:
            with open('result.csv','a',newline='',encoding='utf-8') as f:
                csv.writer(f).writerow([message['payload']['content']])

app = Application()
app._reactor.run()
