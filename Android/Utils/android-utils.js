// Utility functions
function getClassHandle(name) {
    return new Promise((resolve, reject) => {
        Java.perform(() => {
            const loaders = Java.enumerateClassLoadersSync();
            let found = false;

            for (let i = 0; i < loaders.length; i++) {
                const loader = loaders[i];
                const factory = Java.ClassFactory.get(loader);
                try {
                    const klassHandle = factory.use(name);
                    resolve(klassHandle);
                    found = true;
                    break;
                } catch {}
            }

            if (!found) reject("Class not found: " + name);
        });
    });
}

function backtrace() {
    var bt = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new());
    console.log("[*] Backtrace:\n" + bt);
}

global.utils = {
    getClassHandle,
    backtrace
};
