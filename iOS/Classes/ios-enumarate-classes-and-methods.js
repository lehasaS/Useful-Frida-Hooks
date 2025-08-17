/*
 * Name: ios-enumerate-classes-and-methods.js
 * Category: iOS > Enumeration
 * Purpose: Enumerate ObjC classes and methods with optional filter
 * Author: Lehasa
 */

const { logInfo, logError } = global.iosUtils;
const filterMethod = "Certificate";

if (ObjC.available) {
    for (const className in ObjC.classes) {
        if (ObjC.classes.hasOwnProperty(className)) {
            const methods = ObjC.classes[className].$ownMethods;

            methods.forEach(methodName => {
                if (methodName.includes(filterMethod)) {
                    try {
                        const method = ObjC.classes[className][methodName];
                        const argCount = method.argumentTypes.length - 2; // self + _cmd
                        logInfo(`${className}: ${methodName} (Arg Count: ${argCount})`);
                    } catch (err) {
                        logError(`Could not get arguments for ${className}.${methodName}: ${err.message}`);
                    }
                }
            });
        }
    }
} else {
    logError("Objective-C runtime is not available.");
}
