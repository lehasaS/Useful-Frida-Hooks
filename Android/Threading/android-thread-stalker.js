Java.perform(function() {
    var threads = Java.enumerateThreadsSync();
    threads.forEach(function(thread) {
        Stalker.follow(thread.id, {
            events: {
                call: true, // Enable call events
            },
            onCall: function(instrumentationContext) {
               console.log("Thread " + thread.id + " called " + instrumentationContext.from + " -> " + instrumentationContext.to);
            }
        });
    });
});

function logTime(tag) {
    const now = System.currentTimeMillis();
    const threadName = Thread.currentThread().getName();
    console.log(`[${now}] [${threadName}] ${tag}`);
}