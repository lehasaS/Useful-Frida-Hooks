/*
 * Name: ios-enumerate-modules.js
 * Category: iOS > Native
 * Purpose: Enumerate app modules and hook exported functions
 * Author: Lehasa
 */

const { logInfo, logError, logNativeStackTrace } = global.iosUtils;
const bundleId = 'MyApp';

const modules = Process.enumerateModules();
modules.forEach(module => {
    if (module.name.includes(bundleId)) {
        logInfo(`Hooking native functions in: ${module.name}`);

        const exports = Module.enumerateExports(module.name);
        exports.forEach(exp => {
            if (exp.type === 'function') {
                try {
                    Interceptor.attach(exp.address, {
                        onEnter(args) {
                            logInfo(`Function called: ${exp.name}`);
                            logNativeStackTrace(this.context);
                        },
                        onLeave(retval) {
                            logInfo(`Function returned: ${retval}`);
                        }
                    });
                } catch (err) {
                    logError(`Error attaching to: ${exp.name} - ${err}`);
                }
            }
        });
    }
});
