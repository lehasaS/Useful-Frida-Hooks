// Put your intercepting proxy's address here:
const PROXY_HOST = '192.168.1.109';
const PROXY_PORT = 8081;
const DEBUG_MODE = true;
const IGNORED_NON_HTTP_PORTS = [];

const PROXY_HOST_IPv4_BYTES = PROXY_HOST.split('.').map(part => parseInt(part, 10));
const IPv6_MAPPING_PREFIX_BYTES = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff];
const PROXY_HOST_IPv6_BYTES = IPv6_MAPPING_PREFIX_BYTES.concat(PROXY_HOST_IPv4_BYTES);

const connectFn = (
    Module.findExportByName('libc.so', 'connect') ?? // Android
    Module.findExportByName('libc.so.6', 'connect') // Linux
);

if (!connectFn) { // Should always be set, but just in case
    console.warn('Could not find libc connect() function to hook raw traffic');
} else {
    Interceptor.attach(connectFn, {
        onEnter(args) {
            const fd = this.sockFd = args[0].toInt32();
            const sockType = Socket.type(fd);

            const addrPtr = ptr(args[1]);
            const addrLen = args[2].toInt32(); // TODO: Probably not right?
            const addrData = addrPtr.readByteArray(addrLen);

            if (sockType === 'tcp' || sockType === 'tcp6') {
                const portAddrBytes = new DataView(addrData.slice(2, 4));
                const port = portAddrBytes.getUint16(0, false); // Big endian!

                const shouldBeIntercepted = !IGNORED_NON_HTTP_PORTS.includes(port);

                const isIPv6 = sockType === 'tcp6';

                const hostBytes = isIPv6
                    // 16 bytes offset by 8 (2 for family, 2 for port, 4 for flowinfo):
                    ? new Uint8Array(addrData.slice(8, 8 + 16))
                    // 4 bytes, offset by 4 (2 for family, 2 for port)
                    : new Uint8Array(addrData.slice(4, 4 + 4));

                const isIntercepted = port === PROXY_PORT && areArraysEqual(hostBytes,
                    isIPv6
                        ? PROXY_HOST_IPv6_BYTES
                        : PROXY_HOST_IPv4_BYTES
                );

                if (isIntercepted) {
                    this.intercepted = true;
                    return;
                }

                if (!shouldBeIntercepted) {
                    // Not intercecpted, sent to unrecognized port - probably not HTTP(S)
                    if (DEBUG_MODE) {
                        console.debug(`Allowing unintercepted connection to port ${port}`);
                    }
                    return;
                }

                // Otherwise, it's an unintercepted connection that should be captured:

                console.log(`Manually intercepting connection to ${
                    isIPv6
                        ? `[${[...hostBytes].map(x => x.toString(16)).join(':')}]`
                        : [...hostBytes].map(x => x.toString()).join('.')
                }:${port}`);

                // Overwrite the port with the proxy port:
                portAddrBytes.setUint16(0, PROXY_PORT, false); // Big endian
                addrPtr.add(2).writeByteArray(portAddrBytes.buffer);

                // Overwrite the address with the proxy address:
                if (isIPv6) {
                    // Skip 8 bytes: 2 family, 2 port, 4 flowinfo
                    addrPtr.add(8).writeByteArray(PROXY_HOST_IPv6_BYTES);
                } else {
                    // Skip 4 bytes: 2 family, 2 port
                    addrPtr.add(4).writeByteArray(PROXY_HOST_IPv4_BYTES);
                }
                this.intercepted = true;
            } else if (DEBUG_MODE) {
                console.log(`Ignoring ${sockType} connection`);
            }

            // N.b. we ignore all non-TCP connections: both UDP and Unix streams
        },
        onLeave: function (result) {
            if (!this.intercepted) return; // Don't log about connections we don't touch.
            const wasSuccessful = result.toInt32() === 0;

            if (wasSuccessful && !DEBUG_MODE) return;

            const fd = this.sockFd;
            const sockType = Socket.type(fd);
            const address = Socket.peerAddress(fd);

            if (wasSuccessful) {
                console.debug(
                    `Connected ${sockType} fd ${fd} to ${JSON.stringify(address)} (${result.toInt32()})`
                );
            } else {
                console.error(
                    `\n !!! --- Intercepted ${sockType} connection ${fd} failed when redirected to proxy ${PROXY_HOST}:${PROXY_PORT} --- !!!\n` +
                      `         Is your proxy configured correctly?\n`
                );
            }
        }
    });

    console.log(`== Redirecting ${
        IGNORED_NON_HTTP_PORTS.length === 0
        ? 'all'
        : 'all unrecognized'
    } TCP connections to ${PROXY_HOST}:${PROXY_PORT} ==`);
}

const areArraysEqual = (arrayA, arrayB) => {
    if (arrayA.length !== arrayB.length) return false;
    return arrayA.every((x, i) => arrayB[i] === x);
};
