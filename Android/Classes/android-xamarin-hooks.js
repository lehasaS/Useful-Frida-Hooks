/*
 * Name: android-xamarin-hooks.js
 * Category: Android > Classes
 * Purpose: Hook and manipulate Xamarin/Mono managed code, attach to Mono runtime, enumerate classes and methods
 * Author: Lehasa
 * Tags: Xamarin, Mono, Hook, Managed, Frida
 */

const STEALTH = false;
function logInfo(msg){ if(!STEALTH) console.log(`[INFO][Xamarin] ${new Date().toISOString()} ${msg}`); }
function logWarn(msg){ if(!STEALTH) console.warn(`[WARN][Xamarin] ${new Date().toISOString()} ${msg}`); }
function logError(msg){ if(!STEALTH) console.error(`[ERROR][Xamarin] ${new Date().toISOString()} ${msg}`); }

setImmediate(function () {

    // ============================ ExNativeFunction Wrapper ============================
    class ExNativeFunction {
        constructor(address, retType='void', argTypes=[], abi='default') {
            const native = new NativeFunction(address, retType, argTypes, abi);
            native.address = address;
            native.retType = retType;
            native.argTypes = argTypes;
            native.abi = abi;

            native.nativeCallback = callback => new NativeCallback(callback, retType, argTypes, abi);
            native.intercept = options => Interceptor.attach(address, options);
            native.replace = callback => Interceptor.replace(address, native.nativeCallback(callback));

            return native;
        }
    }
    global.ExNativeFunction = ExNativeFunction;

    // ============================ Mono Runtime Detection =============================
    const KNOWN_RUNTIMES = ['mono.dll', 'libmonosgen-2.0.so', 'libmono-native.so'];
    let monoModule = null;

    (function waitForMono() {
        const POLL_INTERVAL = 100;
        const MAX_RETRIES = 100;
        let retries = 0;

        const interval = setInterval(() => {
            try {
                for (const runtime of KNOWN_RUNTIMES) {
                    const module = Process.findModuleByName(runtime);
                    if (module) { monoModule = module; break; }
                }

                if (!monoModule) {
                    const monoThreadAttach = Module.findExportByName(null, 'mono_thread_attach');
                    if (monoThreadAttach) monoModule = Process.findModuleByAddress(monoThreadAttach);
                }

                if (monoModule) {
                    logInfo(`Mono runtime found: ${monoModule.name}`);
                    MonoApi.module = monoModule;
                    clearInterval(interval);
                } else if (retries++ >= MAX_RETRIES) {
                    logError('Failed to find Mono runtime after maximum retries.');
                    clearInterval(interval);
                }
            } catch(e) {
                logError('Error in Mono detection loop: ' + e);
                clearInterval(interval);
            }
        }, POLL_INTERVAL);
    })();

    // ============================ Mono API Definitions ===============================
    const MONO_TABLE_TYPEDEF = 2;
    const MONO_TOKEN_TYPE_DEF = 0x02000000;

    let MonoApi = {
        mono_assembly_foreach: ['void', ['pointer', 'pointer']],
        mono_runtime_invoke: ['pointer', ['pointer', 'pointer', 'pointer', 'pointer']],
        mono_assembly_get_image: ['pointer', ['pointer']],
        mono_class_from_name: ['pointer', ['pointer', 'pointer', 'pointer']],
        mono_class_get_method_from_name: ['pointer', ['pointer', 'pointer', 'int']],
        mono_compile_method: ['pointer', ['pointer']],
        mono_get_root_domain: ['pointer'],
        mono_class_enum_basetype: ['pointer', ['pointer']],
        mono_class_is_enum: ['uchar', ['pointer']],
        mono_get_corlib: ['pointer'],
        mono_string_new: ['pointer', ['pointer', 'pointer']],
        mono_domain_get: ['pointer'],
        mono_string_to_utf8: ['pointer', ['pointer']],
        mono_thread_attach: ['pointer', ['pointer']],
        mono_array_length: ['uint32', ['pointer']],
        mono_array_addr_with_size: ['pointer', ['pointer', 'int', 'uint32']],
        mono_object_get_class: ['pointer', ['pointer']],
        mono_class_get_fields: ['pointer', ['pointer', 'pointer']],
        mono_class_get_name: ['pointer', ['pointer']],
        mono_class_get_namespace: ['pointer', ['pointer']],
        mono_image_get_table_rows: ['int', ['pointer', 'int']],
        mono_class_get: ['pointer', ['pointer', 'int']],
    };

    Object.keys(MonoApi).forEach(exportName => {
        if (MonoApi[exportName] === null) {
            MonoApi[exportName] = () => { throw new Error('Export signature missing: ' + exportName); };
        } else {
            const addr = Module.findExportByName('libmonosgen-2.0.so', exportName);
            MonoApi[exportName] = !addr
                ? () => { throw new Error('Export not found: ' + exportName); }
                : new ExNativeFunction(addr, ...MonoApi[exportName]);
        }
    });

    // Attach to root domain
    MonoApi.mono_thread_attach(MonoApi.mono_get_root_domain());
    MonoApi.module = monoModule;

    // ============================ Mono Helpers ======================================
    const rootDomain = MonoApi.mono_get_root_domain();
    const MonoApiHelper = {
        AssemblyForeach: cb => MonoApi.mono_assembly_foreach(MonoApi.mono_assembly_foreach.nativeCallback(cb), NULL),
        ClassGetNamespace: mono_class => Memory.readUtf8String(MonoApi.mono_class_get_namespace(mono_class)),
        ClassFromAssembly: (assembly, namespace, className) => {
            const image = MonoApi.mono_assembly_get_image(assembly);
            return MonoApi.mono_class_from_name(image, namespace, className);
        },
        ClassGetMethodFromName: (klass, name, argCnt=-1) => MonoApi.mono_class_get_method_from_name(klass, Memory.allocUtf8String(name), argCnt),
        ClassGetName: klass => Memory.readUtf8String(MonoApi.mono_class_get_name(klass)),
        ClassGetFields: klass => {
            const fields = [];
            const iter = Memory.alloc(Process.pointerSize);
            let field;
            while (!(field = MonoApi.mono_class_get_fields(klass, iter)).isNull()) fields.push(field);
            return fields;
        },
        StringNew: str => MonoApi.mono_string_new(rootDomain, Memory.allocUtf8String(str)),
    };

    // ============================ Utility Functions =================================
    function resolveClassName(className){
        return {
            className: className.substring(className.lastIndexOf('.')+1),
            namespace: className.substring(0, className.lastIndexOf('.'))
        };
    }

    function getClassByName(class_name){
        let result = null;
        MonoApiHelper.AssemblyForeach(assembly => {
            const image = MonoApi.mono_assembly_get_image(assembly);
            const klass = MonoApiHelper.ClassFromName(image, class_name);
            if (klass !== 0) result = klass;
        });
        return result;
    }

    function hookManagedMethod(klass, methodName, callbacks){
        if (!callbacks) throw new Error('callbacks must be an object!');
        if (!callbacks.onEnter && !callbacks.onLeave) throw new Error('At least one callback is required!');
        const md = MonoApiHelper.ClassGetMethodFromName(klass, methodName);
        if (!md) throw new Error('Method not found: ' + methodName);
        const impl = MonoApi.mono_compile_method(md);
        Interceptor.attach(impl, {...callbacks});
    }

    // ============================ Mono Workspace ====================================
    let assemblies = [];
    MonoApi.mono_assembly_foreach(new NativeCallback((assembly, userData) => { assemblies.push(assembly); }, 'void', ['pointer','pointer']), NULL);

    // ============================ Example Hook ======================================
    const DEBUG = false;
    // Replace placeholders with actual namespace/class/method
    hook('<Namespace>', '<ClassName>', '<MethodName>', {
        onEnter: function(args){
            logInfo(`Hooked <MethodName> in <ClassName>`);
            try {
                logInfo("[Arg0]: " + Memory.readUtf8String(MonoApi.mono_string_to_utf8(args[0])));
            } catch(e) { logWarn("Failed reading argument: " + e); }
        },
        onLeave: function(retval){}
    });

});
