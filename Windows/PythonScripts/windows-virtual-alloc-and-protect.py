import frida, time, argparse

parser = argparse.ArgumentParser()
parser.add_argument("-f","--file",required=True)
args = parser.parse_args()

pid = frida.spawn(args.file)
session = frida.attach(pid)
time.sleep(1)

script_source = """
        function safeHex(ptr, size=64){
            try { return hexdump(ptr, {length:size, ansi:true}); }
            catch(e){ return "<cannot read memory>"; }
        }

        var vaExportAddress = Module.getExportByName("KERNEL32.DLL", "VirtualAlloc");
        var vpExportAddress = Module.getExportByName("KERNEL32.DLL", "VirtualProtect");
                               
        Interceptor.attach(vaExportAddress, 
        {
            onEnter: function(args)
            {
                var vaSize = args[1].toInt32();
                var vaProtect = args[3];
                console.log("\\nVirtualAlloc called => Size: " + vaSize + " | Protection: " + vaProtect);
                console.log(`Hexdump (first 64 bytes): ` + safeHex(retval));
            },
            onLeave: function(retval)
            {
                console.log("VirtualAlloc returned => Address: " + retval);
            }
        });
                               
        Interceptor.attach(vpExportAddress, 
        {
            onEnter: function(args)
            {
                var vpAddress = args[0];
                var vpSize = args[1].toInt32();
                var vpProtect = args[2];
                console.log("\\nVirtualProtect called => Address: " + vpAddress + " | Size: " + vpSize + " | New Protection: " + vpProtect);
                console.log(`Hexdump (first 64 bytes): ` + safeHex(retval));
            }                       
        });
    """

script = session.create_script(script_source)
script.load()
frida.resume(pid)