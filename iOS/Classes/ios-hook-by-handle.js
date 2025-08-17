/*
 * Name: ios-hook-by-handle.js
 * Category: iOS > Hooking
 * Purpose: Hook a specific ObjC class and modify return values
 * Author: Lehasa
 */

const { logInfo, logError, getClassHandle } = global.iosUtils;

async function hookMyClass() {
    try {
        const MyClass = await getClassHandle("MyClass");
        logInfo(`Hooking class: ${MyClass}`);

        MyClass.$ownMethods.forEach(methodName => {
            const method = MyClass[methodName];
            if (method && methodName.includes("isJailBroken")) {
                Interceptor.attach(method.implementation, {
                    onEnter(args) {
                        logInfo(`Entered method: ${methodName}`);
                    },
                    onLeave(retval) {
                        logInfo(`Original return value: ${retval}`);
                        retval.replace(new NativePointer(0x00));
                        logInfo(`Modified return value: ${retval}`);
                    }
                });
            }
        });
    } catch (error) {
        logError(error.message);
    }
}

hookMyClass();
