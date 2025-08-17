/*
 * Name: android-hook-by-handle.js
 * Category: Android > Classes
 * Purpose: Acquire a class handle via loader scan, then hook a target method
 * Author: Lehasa
 * Tags: Classes, Hook, Dynamic
 */
const { getClassHandle } = global.utils; 
const STEALTH = false;
function logInfo(msg){ if(!STEALTH) console.log(`[INFO][Hook] ${new Date().toISOString()} ${msg}`); }
function logWarn(msg){ if(!STEALTH) console.warn(`[WARN][Hook] ${new Date().toISOString()} ${msg}`); }
function logError(msg){ if(!STEALTH) console.error(`[ERROR][Hook] ${new Date().toISOString()} ${msg}`); }

const TARGET_CLASS = "myapp";
const TARGET_METHOD = "verify";

function argToString(a){
    try{ return a === null || a === undefined ? String(a) : a.toString(); } catch{ return "[UnprintableArg]"; }
}

function coerceSuccess(ret, overload){
    try{
        if(ret===false || ret===null || ret===undefined || String(ret).toUpperCase().includes("FAIL")){
            if(ret && ret.SUCCESS) return ret.SUCCESS.value || ret.SUCCESS;
            if(typeof ret === "boolean") return true;
            if(typeof ret === "string") return "SUCCESS";
            if(typeof ret === "number") return 0;
        }
        return ret;
    } catch{ return ret; }
}


async function main(){
    try{
        const klass = await getClassHandle(TARGET_CLASS);
        if(!klass[TARGET_METHOD]) return logError(`Method not found: ${TARGET_CLASS}.${TARGET_METHOD}`);

        klass[TARGET_METHOD].overloads.forEach((ovl, idx)=>{
            ovl.implementation = function(){
                const args = Array.from(arguments);
                logInfo(`Entered ${TARGET_METHOD}#${idx} with args: ${args.map(argToString).join(', ')}`);
                const ret = ovl.apply(this,args);
                const finalRet = coerceSuccess(ret,ovl);
                logInfo(`Returning: ${argToString(finalRet)}`);
                return finalRet;
            };
        });

        logInfo("Hook attached");
    } catch(e){ logError("Hook setup failed: "+e); }
}

Java.perform(main);
