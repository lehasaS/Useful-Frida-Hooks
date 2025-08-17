import frida
import threading
from frida_tools.application import Reactor
import csv

# CSV setup
with open('result.csv', 'w', newline='', encoding='utf-8') as file:
    writer = csv.writer(file)
    writer.writerow(["UTF-16", "HexDump"])

# Helper for safe memory reading
def safe_utf16(ptr):
    try:
        return ptr.readUtf16String()
    except Exception:
        return "<invalid UTF-16>"

def safe_hexdump(ptr, size=64):
    try:
        return ptr.readByteArray(size)
    except Exception:
        return b"<cannot read memory>"

class Application:
    def __init__(self):
        self._stop_requested = threading.Event()
        self._reactor = Reactor(run_until_return=lambda r: self._stop_requested.wait())
        self._device = frida.get_local_device()
        self._sessions = set()

        # Frida child gating events
        self._device.on("child-added", lambda child: self._reactor.schedule(lambda: self._on_child_added(child)))
        self._device.on("child-removed", lambda child: self._reactor.schedule(lambda: self._on_child_removed(child)))
        self._device.on("output", lambda pid, fd, data: self._reactor.schedule(lambda: self._on_output(pid, fd, data)))

    def run(self, target_exe="test.exe"):
        try:
            self._reactor.schedule(lambda: self._start(target_exe))
            self._reactor.run()
        except KeyboardInterrupt:
            print("[-] Interrupted by user. Stopping...")
            self._stop_requested.set()

    def _start(self, exe_name):
        print(f"[+] Spawning {exe_name}")
        pid = self._device.spawn([exe_name], env={}, stdio='pipe')
        self._instrument(pid)

    def _stop_if_idle(self):
        if len(self._sessions) == 0:
            self._stop_requested.set()

    def _instrument(self, pid):
        print(f"[+] Instrumenting PID {pid}")
        try:
            session = self._device.attach(pid)
            session.on("detached", lambda reason: self._reactor.schedule(lambda: self._on_detached(pid, session, reason)))

            # Enable child gating
            print("[+] Enabling child gating")
            session.enable_child_gating()

            # Load hooks
            with open('./instrumentation-hooks.js', 'r') as fd:
                script_content = fd.read()
            script = session.create_script(script_content)
            script.on("message", lambda message, data: self._reactor.schedule(lambda: self._on_message(pid, message)))
            script.load()

            self._device.resume(pid)
            self._sessions.add(session)
        except frida.ProcessNotFoundError:
            print(f"[-] Process {pid} not found.")
        except frida.PermissionDeniedError:
            print(f"[-] Permission denied for PID {pid}.")
        except Exception as e:
            print(f"[-] Failed to attach PID {pid}: {e}")

    # Child gating handlers
    def _on_child_added(self, child):
        print(f"[+] Child process added: {child}")
        self._instrument(child.pid)
        self._device.resume(child.pid)

    def _on_child_removed(self, child):
        print(f"[-] Child process removed: {child}")

    def _on_output(self, pid, fd, data):
        print(f"[+] Output from PID {pid} | fd={fd} | Data={repr(data)}")

    def _on_detached(self, pid, session, reason):
        print(f"[-] Detached from PID {pid} | Reason: {reason}")
        self._sessions.discard(session)
        self._reactor.schedule(self._stop_if_idle, delay=0.5)
        if len(self._sessions) == 0 and self._stop_requested.is_set():
            self._reactor.stop()

    def _on_message(self, pid, message):
        if not message or 'payload' not in message:
            print(f"[-] PID {pid} message has no payload: {message}")
            return

        payload = message['payload']
        utf16_content = payload.get('content', "<no content>")
        hexdump_content = payload.get('hex', "<no hexdump>")

        print(f"[+] PID {pid} payload: {utf16_content}")

        try:
            with open('result.csv', 'a', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow([utf16_content, hexdump_content])
        except Exception as e:
            print(f"[-] Failed to write CSV: {e}")


if __name__ == "__main__":
    app = Application()
    app.run()
