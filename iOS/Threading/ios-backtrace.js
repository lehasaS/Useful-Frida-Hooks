function logNativeStackTrace(context) {
    var stack = Thread.backtrace(context, Backtracer.FUZZY); 
    var symbols = stack.map(DebugSymbol.fromAddress); // Convert addresses to symbols
    console.log("[+] Current Call Stack:");
    symbols.forEach(function (symbol) {
        console.log(symbol); // Log each symbol in the call stack
    });
}

// Call with logNativeStackTrace(this.context);