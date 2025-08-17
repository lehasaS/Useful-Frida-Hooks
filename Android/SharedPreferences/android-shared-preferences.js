// Java.perform(() => {
// 	const sharedPreferences = Java.use('android.app.SharedPreferencesImpl');
// 	sharedPreferences.getString.overload('java.lang.String', 'java.lang.String').implementation = (value, defaultvalue) => { 
// 		console.log("on_enter parameters", value, defaultvalue); 
// 		const returnedString = this.getString(value, defaultvalue);
// 		console.log("returnedString", returnedString); 
// 		return returnedString;
// 	};
// });


Java.perform(function () {
    // Hook the SharedPreferences class
    const SharedPreferences = Java.use('android.content.SharedPreferences');

    // Hook the putString method to log data being stored
    const SharedPreferencesEditor = Java.use('android.content.SharedPreferences$Editor');
    SharedPreferencesEditor.putString.implementation = function (key, value) {
        console.log("[*] Storing in SharedPreferences - Key:", key, "Value:", value);
        return this.putString(key, value);
    };

    // Hook getString method to log data being retrieved
    SharedPreferences.getString.overload('java.lang.String', 'java.lang.String').implementation = function (key, defValue) {
        console.log("on_enter parameters", key, defValue);
        const result = this.getString(key, defValue);
        console.log("[*] Retrieving from SharedPreferences - Key:", key, "Value:", result);
        return result;
    };

    // Additional hooks for other data types
    // Hook putInt, putBoolean, putFloat, putLong, and get methods
    const types = ['Int', 'Boolean'];
    types.forEach(function (type) {
        SharedPreferencesEditor['put' + type].implementation = function (key, value) {
            console.log(`[*] Storing in SharedPreferences - Key: ${key}, Value: ${value}`);
            return this['put' + type](key, value);
        };
        
        SharedPreferences['get' + type].overload('java.lang.String', type === 'Boolean' ? 'boolean' : 'int').implementation = function (key, defValue) {
            const result = this['get' + type](key, defValue);
            console.log(`[*] Retrieving from SharedPreferences - Key: ${key}, Value: ${result}`);
            return result;
        };
    });

    // Log EncryptedSharedPreferences values in a similar way
    const EncryptedSharedPreferences = Java.use('androidx.security.crypto.EncryptedSharedPreferences');

    EncryptedSharedPreferences.getString.overload('java.lang.String', 'java.lang.String').implementation = function (key, defValue) {
        const result = this.getString(key, defValue);
        console.log("[*] Retrieving from EncryptedSharedPreferences - Key:", key, "Value:", result);
        return result;
    };

    SharedPreferencesEditor.putString.overload('java.lang.String', 'java.lang.String').implementation = function (key, value) {
        console.log("[*] Storing in EncryptedSharedPreferences - Key:", key, "Value:", value);
        return this.putString(key, value);
    };
});


Java.perform(function () {
    const MasterKeys = Java.use('androidx.security.crypto.MasterKeys');
    
    // Hook getOrCreate to reveal the master key alias
    MasterKeys.getOrCreate.implementation = function (keyGenParameterSpec) {
        const keyAlias = this.getOrCreate(keyGenParameterSpec);
        console.log("[*] Master Key Alias:", keyAlias);
        return keyAlias;
    };
    const EncryptedSharedPreferences = Java.use('androidx.security.crypto.EncryptedSharedPreferences');
    EncryptedSharedPreferences.create.overload('android.content.Context', 'java.lang.String', 'androidx.security.crypto.MasterKey', 'androidx.security.crypto.EncryptedSharedPreferences$PrefKeyEncryptionScheme', 'androidx.security.crypto.EncryptedSharedPreferences$PrefValueEncryptionScheme').implementation = function (fileName, prefKey, context, masterKey, keyScheme) {
        console.log("[*] EncryptedSharedPreferences.create called with:");
        console.log("    - File Name:", prefKey);
        console.log("    - Pref Key:", context);
        console.log("    - Master Key Alias:", masterKey.getAlias());
        return this.create(fileName, prefKey, context, masterKey, keyScheme);
    };

	



	const encryptedSharedPreferences = Java.use('androidx.security.crypto.EncryptedSharedPreferences');
    encryptedSharedPreferences.create.overload('java.lang.String', 'java.lang.String', 'android.content.Context', 'androidx.security.crypto.EncryptedSharedPreferences$PrefKeyEncryptionScheme', 'androidx.security.crypto.EncryptedSharedPreferences$PrefValueEncryptionScheme').implementation = function (fileName, other, prefKey, masterKey, valueScheme) {
        console.log("[*] EncryptedSharedPreferences.create called with:");
        console.log("    - File Name:", fileName);
		console.log("    - File Name:", other);
        console.log("    - Key Scheme:", masterKey);
		console.log("    - Value Scheme:", valueScheme);
        return this.create(fileName, prefKey, masterKey, keyScheme, valueScheme);
    };

});
