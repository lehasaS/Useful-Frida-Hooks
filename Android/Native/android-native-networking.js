console.log("[+] Starting Android Network Hooks");

// Helper to read sockaddr_in and extract IP:Port
function parseSockaddrIn(sockaddrPtr) {
    if (sockaddrPtr.isNull()) return null;

    var family = sockaddrPtr.readU16(); // sa_family
    if (family !== 2) return null; // AF_INET = 2

    var port = ((sockaddrPtr.add(2).readU8() << 8) | sockaddrPtr.add(3).readU8()) & 0xffff;
    var ip = sockaddrPtr.add(4).readU8() + "." +
             sockaddrPtr.add(5).readU8() + "." +
             sockaddrPtr.add(6).readU8() + "." +
             sockaddrPtr.add(7).readU8();
    return { ip: ip, port: port };
}

// Hook connect()
Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
    onEnter: function(args) {
        this.fd = args[0].toInt32();
        var sockaddr = parseSockaddrIn(args[1]);
        if (sockaddr) {
            console.log(`[+] connect(fd=${this.fd}) to ${sockaddr.ip}:${sockaddr.port}`);
            send({ type: "Network Connect", fd: this.fd, ip: sockaddr.ip, port: sockaddr.port });
        }
    },
    onLeave: function(retval) {}
});

// Hook send()
Interceptor.attach(Module.findExportByName("libc.so", "send"), {
    onEnter: function(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();

        try {
            var payload = Memory.readByteArray(this.buf, this.len);
            console.log(`[+] send(fd=${this.fd}, length=${this.len})`);
            send({ type: "Network Send", fd: this.fd, length: this.len, data: payload });
        } catch (err) {
            console.log("[-] Failed to read send buffer: " + err);
        }
    },
    onLeave: function(retval) {}
});

// Hook recv()
Interceptor.attach(Module.findExportByName("libc.so", "recv"), {
    onEnter: function(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave: function(retval) {
        var received = retval.toInt32();
        if (received > 0) {
            try {
                var payload = Memory.readByteArray(this.buf, received);
                console.log(`[+] recv(fd=${this.fd}, received=${received})`);
                send({ type: "Network Recv", fd: this.fd, length: received, data: payload });
            } catch (err) {
                console.log("[-] Failed to read recv buffer: " + err);
            }
        }
    }
});

// Hook sendto()
Interceptor.attach(Module.findExportByName("libc.so", "sendto"), {
    onEnter: function(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
        var sockaddr = parseSockaddrIn(args[4]);
        if (sockaddr) {
            console.log(`[+] sendto(fd=${this.fd}) to ${sockaddr.ip}:${sockaddr.port}`);
            send({ type: "Network SendTo", fd: this.fd, ip: sockaddr.ip, port: sockaddr.port });
        }
    },
    onLeave: function(retval) {}
});

// Hook recvfrom()
Interceptor.attach(Module.findExportByName("libc.so", "recvfrom"), {
    onEnter: function(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave: function(retval) {
        var received = retval.toInt32();
        if (received > 0) {
            try {
                var payload = Memory.readByteArray(this.buf, received);
                console.log(`[+] recvfrom(fd=${this.fd}, received=${received})`);
                send({ type: "Network RecvFrom", fd: this.fd, length: received, data: payload });
            } catch (err) {
                console.log("[-] Failed to read recvfrom buffer: " + err);
            }
        }
    }
});

console.log("[+] Android Network Hooks Loaded");
