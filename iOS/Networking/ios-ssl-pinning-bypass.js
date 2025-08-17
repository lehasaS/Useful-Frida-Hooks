if (ObjC.available) {
    try {
        const SSL_CTX_set_custom_verify = Module.findExportByName(null, 'SSL_CTX_set_custom_verify');
        const SSL_VERIFY_NONE = 0;  // OpenSSL constant for SSL_VERIFY_NONE

        if (SSL_CTX_set_custom_verify) {
            if (!Interceptor.hasOwnProperty("SSL_CTX_set_custom_verify_hooked")) {
                Interceptor.attach(SSL_CTX_set_custom_verify, {
                    onEnter: function(args) {
                        console.log("SSL_CTX_set_custom_verify called");

                        // Hook the custom verification callback function
                        const callback = new NativeFunction(args[2], 'int', ['pointer', 'pointer']);
                        Interceptor.replace(callback, new NativeCallback(function(ssl, ctx) {
                            console.log("Called custom SSL context verify callback, returning SSL_VERIFY_NONE.");
                            return SSL_VERIFY_NONE;
                        }, 'int', ['pointer', 'pointer']));

                        console.log("Custom SSL verification callback replaced with SSL_VERIFY_NONE");
                    }
                });

                // Mark the function as hooked to prevent duplicate hooks
                Interceptor.SSL_CTX_set_custom_verify_hooked = true;
            } else {
                console.log("SSL_CTX_set_custom_verify is already hooked.");
            }

        } else {
            console.log("SSL_CTX_set_custom_verify not found");
        }

    } catch (error) {
        console.error("Error hooking SSL verification functions:", error);
    }
} else {
    console.log("Objective-C runtime not available.");
}