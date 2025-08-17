const Runtime = Java.use("java.lang.Runtime");

Runtime.exec.overload("java.lang.String").implementation = function (command) {
    console.log("Command Executed: " + command);
    return this.exec(command);
};

Runtime["exec"].overload('java.lang.String', '[Ljava.lang.String;').implementation = function (str, strArr) {
    console.log(`Runtime.exec() is called: str=${str}, strArr=${strArr}`);
    let result = Runtime["exec"](str, strArr);
    console.log(`Runtime exec() result=${result}`);
    return this.exec(str, strArr);

};