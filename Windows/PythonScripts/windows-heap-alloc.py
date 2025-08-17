import frida, csv, threading
from frida_tools.application import Reactor

malware_directory = "C:\\malware"

with open('result.csv','w',newline='') as f:
    csv.writer(f).writerow(["UTF-16", "HexDump"])

script_source = """
function safeUtf16(ptr){ try { return ptr.readUtf16String(); } catch(e){ return "<invalid>"; } }
function safeHex(ptr, size=64){ try { return hexdump(ptr, {length:size, ansi:true}); } catch(e){ return "<cannot read memory>"; } }

Interceptor.attach(Module.findExportByName('kernel32.dll', 'HeapAlloc'), {
    onLeave: function(retval){
        if(!retval.isNull()){
            let content = safeUtf16(retval);
            let hexdata = safeHex(retval);
            send({'utf16': content, 'hex': hexdata});
        }
    }
});
"""
class Application:
    def __init__(self):
        self._stop = threading.Event()
        self._reactor = Reactor(run_until_return=lambda r:self._stop.wait())
        self._device = frida.get_local_device()
        self._sessions = set()
        self.check_new_process()

    def check_new_process(self):
        for p in self._device.enumerate_processes():
            if p.name in ['rundll32.exe','regsvr32.exe'] and p.pid not in self._sessions:
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
