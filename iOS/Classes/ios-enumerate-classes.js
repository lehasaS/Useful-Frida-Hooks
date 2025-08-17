/*
 * Name: ios-enumerate-classes.js
 * Category: iOS > Enumeration
 * Purpose: Enumerate all ObjC classes with optional filter
 * Author: Lehasa
 */

const { logInfo, logError } = global.iosUtils;
const filterClass = "jail";

if (ObjC.available) {
    for (const className in ObjC.classes) {
        if (ObjC.classes.hasOwnProperty(className)) {
            if (!filterClass || className.includes(filterClass)) {
                logInfo(`[+] Class found: ${className}`);
            }
        }
    }
} else {
    logError("Objective-C runtime is not available.");
}
