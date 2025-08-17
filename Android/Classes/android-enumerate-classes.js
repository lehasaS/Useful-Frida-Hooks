/*
 * Name: android-enumerate-classes.js
 * Category: Android > Classes
 * Purpose: List loaded classes whose name contains a keyword
 * Author: Lehasa
 * Tags: Classes, Enumeration
 */

const STEALTH = false;
function logInfo(msg){ if(!STEALTH) console.log(`[INFO][Classes] ${new Date().toISOString()} ${msg}`); }
function logError(msg){ if(!STEALTH) console.error(`[ERROR][Classes] ${new Date().toISOString()} ${msg}`); }

Java.perform(function() {
    var pattern = "Pin";    
	
	try {
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                if (className.includes(pattern)) {
                    try {
                        logInfo(className);
                    } catch (e) {
                        logError("Failed to hook class: " + className + " Error: " + e);
                    }
                }
            },
            onComplete: function() {
                logInfo("Class enumeration completed"); 
            }
        });
    } catch (error) {
        logError("Enumeration failed: " + error);
    }
});
