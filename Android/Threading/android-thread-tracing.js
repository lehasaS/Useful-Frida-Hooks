Java.perform(function() {
    Java.choose("java.lang.Thread", {
        onMatch: function(instance) {
            console.log("Thread: " + instance.getName() + " (" + instance.getId() + ")");
        },
        onComplete: function() {}
    });
});

function logTime(tag) {
    const now = System.currentTimeMillis();
    const threadName = Thread.currentThread().getName();
    console.log(`[${now}] [${threadName}] ${tag}`);
}