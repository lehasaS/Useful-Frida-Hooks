Java.perform(() => {
    const { getClassHandle } = global.utils; // Assuming you have a utility module

    // -----------------------------
    // Helper: Print Java stack trace
    // -----------------------------
    function logBacktrace() {
        const Log = Java.use('android.util.Log');
        const Exception = Java.use('java.lang.Exception');
        const stack = Log.getStackTraceString(Exception.$new());
        console.log("[*] Backtrace:\n" + stack);
    }

    // -----------------------------
    // Hook OkHttp3 Requests
    // -----------------------------
    getClassHandle("okhttp3.Request$Builder")
        .then(OkHttpRequestBuilder => {
            OkHttpRequestBuilder.build.implementation = function() {
                logBacktrace(); // Optional: log backtrace when build() is called

                const request = this.build();
                const url = request.url().toString();

                // Filter URLs if needed
                if (url.includes("/mobile/logs")) {
                    console.log("[*] Intercepted OkHttp request to " + url);

                    // HTTP method
                    const method = request.method();
                    console.log("[*] HTTP Method: " + method);

                    // Request body
                    const body = request.body();
                    if (body) {
                        const Buffer = Java.use('okio.Buffer');
                        const buffer = Buffer.$new();
                        body.writeTo(buffer);
                        const requestBody = buffer.readUtf8();
                        console.log("[*] Data before encryption: " + requestBody);
                    }
                }
                return request;
            };
        })
        .catch(error => console.error("[!] OkHttp hook error:", error));

    // -----------------------------
    // Hook HttpURLConnection
    // -----------------------------
    getClassHandle("java.net.HttpURLConnection")
        .then(HttpURLConnection => {
            HttpURLConnection.getOutputStream.implementation = function() {
                const url = this.getURL().toString();
                if (url.includes("/mobile/logs")) {
                    console.log("[*] Intercepted HttpURLConnection request to " + url);

                    const outputStream = this.getOutputStream();
                    const OutputStreamWriter = Java.use("java.io.OutputStreamWriter");
                    const BufferedWriter = Java.use("java.io.BufferedWriter");

                    const writerInstance = OutputStreamWriter.$new(outputStream);
                    const bufferedWriterInstance = BufferedWriter.$new(writerInstance);

                    // Hook write(String) to log payload
                    bufferedWriterInstance.write.overload("java.lang.String").implementation = function(data) {
                        console.log("[*] Data before encryption: " + data);
                        return this.write(data); // Call original
                    };
                }
                return this.getOutputStream();
            };
        })
        .catch(error => console.error("[!] HttpURLConnection hook error:", error));
});
