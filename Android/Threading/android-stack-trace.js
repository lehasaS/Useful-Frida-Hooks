function backtrace() {
    var backtrace = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new());
    console.log("[*] Backtrace:\n" + backtrace);
}

// backtrace();