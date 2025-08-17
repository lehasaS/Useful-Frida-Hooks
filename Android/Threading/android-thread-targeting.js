Java.perform(function() {
    var targetThreadId = null; /* Specify the ID of the target thread */
    var targetMethod = Java.use("java.lang.Thread").run; 

    Interceptor.attach(targetMethod.implementation, {
        onEnter: function(args) {
            var currentThread = Java.Thread.currentThread();
            if (currentThread.getId() === targetThreadId) {
                console.log("Entering run() in target thread: " + currentThread.getName());
                // Perform actions specific to the target thread
            }
        },
        onLeave: function(retval) {
            var currentThread = Java.Thread.currentThread();
            if (currentThread.getId() === targetThreadId) {
               console.log("Leaving run() in target thread: " + currentThread.getName());
            }
        }
    });
});

function logTime(tag) {
    const now = System.currentTimeMillis();
    const threadName = Thread.currentThread().getName();
    console.log(`[${now}] [${threadName}] ${tag}`);
}