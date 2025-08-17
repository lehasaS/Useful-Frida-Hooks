Java.perform(function() {
    var Thread = Java.use('java.lang.Thread');
    var Runnable = Java.use('java.lang.Runnable');

    var MyRunnable = Java.registerClass({
        name: 'com.example.MyRunnable',
        implements: [Runnable],
        methods: {
            run: function() {
                console.log('[+] MyRunnable.run() called from thread: ' + Thread.currentThread().getName());
                this.run.implementation.call(this); // Call the original implementation
            }
        }
    });

    Thread.start.implementation = function() {
        var runnable = this.$r;
        if (runnable) {
            if (runnable.getClass().getName() === 'com.example.MyRunnable'){
              runnable.run = MyRunnable.prototype.run.bind(runnable);
            }
        }
        this.start.implementation.call(this);
    };
});

function logTime(tag) {
    const now = System.currentTimeMillis();
    const threadName = Thread.currentThread().getName();
    console.log(`[${now}] [${threadName}] ${tag}`);
}