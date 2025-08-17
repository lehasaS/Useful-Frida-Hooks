Java.perform(function() {
    var Thread = Java.use('java.lang.Thread');

    var currentThread = Java.Thread.currentThread();
    console.log("Current thread: " + currentThread.getName() + " (" + currentThread.getId() + ")");

    // Hook Thread constructor
    var threadInit = Thread.$init.overload(java.lang.Runnable.class, java.lang.String.class);
    threadInit.implementation = function(runnable, threadName) {
        console.log("[+] Thread created: " + threadName);
        // Call original constructor
        this.$init(runnable, threadName);
    };

    // Hook Thread.start()
    Thread.start.implementation = function() {
        console.log("[+] Thread started: " + this.getName());
        // Call original start method
        this.start();
    };
    
    // Enumerate existing threads
    Java.enumerateThreads({
        onMatch: function(thread) {
            console.log("[*] Existing thread: " + thread.name);
        },
        onComplete: function() {
            console.log("[*] Finished enumerating threads");
        }
    });

    // Example of hooking a method within a specific thread
    var MyClass = Java.use("your.package.MyClass");
    MyClass.myMethod.implementation = function() {
        var currentThread = Thread.currentThread();
        if (currentThread.getName() === "TargetThreadName") {
          console.log("[+] myMethod called within TargetThreadName");
        }
        return this.myMethod();
    };
});

function logTime(tag) {
    const now = System.currentTimeMillis();
    const threadName = Thread.currentThread().getName();
    console.log(`[${now}] [${threadName}] ${tag}`);
}