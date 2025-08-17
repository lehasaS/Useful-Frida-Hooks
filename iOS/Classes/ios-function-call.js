/*
 * Name: ios-function-call.js
 * Category: iOS > Native
 * Purpose: Demonstrates calling a native function from Frida
 * Author: Lehasa
 */

const { logInfo, logError } = global.iosUtils;

// Find the address
const func_addr = Module.findExportByName("<Prog Name>", "<Func Name>");
const func = new NativeFunction(func_addr, "void", ["pointer", "pointer", "pointer"]);

let arg0 = null;

// Intercept to capture arg0
Interceptor.attach(func_addr, {
    onEnter(args) {
        arg0 = new NativePointer(args[0]);
    }
});

// Wait for a call to occur
while (!arg0) {
    Thread.sleep(1);
    logInfo("Waiting for function pointer...");
}

const arg1 = Memory.allocUtf8String('arg1');
const arg2 = Memory.allocUtf8String('Some text for arg2');

func(arg0, arg1, arg2);
logInfo("Function called successfully");
