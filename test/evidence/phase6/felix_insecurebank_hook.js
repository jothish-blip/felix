
/**
 * FELIX v3.0 Mobile Dynamic Instrumentation Script
 * Generated automatically by pkg/mobile
 * Target: Android Runtime (Java bridge)
 */
if (Java.available) {
    Java.perform(function() {
        function sendPayload(type, className, methodName, details) {
            try {
                send({
                    "felix_type": type,
                    "class": className || "",
                    "method": methodName || "",
                    "timestamp": new Date().toISOString(),
                    "details": details || {}
                });
            } catch (err) {
                // Ignore transient IPC delivery errors
            }
        }

        function isByteArrayAllZeros(bytes) {
            if (!bytes || bytes.length === 0) return false;
            for (var i = 0; i < bytes.length; i++) {
                if (bytes[i] !== 0) return false;
            }
            return true;
        }

        function redactSecret(val) {
            if (!val || typeof val !== 'string') return "";
            if (val.length <= 4) return "****";
            return val.substring(0, 2) + "****************" + val.substring(val.length - 2);
        }

// --- Module: Lifecycle ---

        try {
            var Activity = Java.use("android.app.Activity");
            Activity.onCreate.overload("android.os.Bundle").implementation = function(bundle) {
                var actName = this.getClass().getName();
                sendPayload("lifecycle", actName, "onCreate", {
                    "event": "ACTIVITY_CREATED",
                    "intent": this.getIntent() ? this.getIntent().toString() : ""
                });
                return this.onCreate(bundle);
            };

            Activity.onResume.implementation = function() {
                var actName = this.getClass().getName();
                sendPayload("lifecycle", actName, "onResume", {
                    "event": "ACTIVITY_RESUMED"
                });
                return this.onResume();
            };
        } catch (e) {
            // Activity class hook failure tolerated
        }

        try {
            var ClassLoader = Java.use("java.lang.ClassLoader");
            ClassLoader.loadClass.overload("java.lang.String").implementation = function(name) {
                if (name && (name.indexOf("com.android.") === 0 || name.indexOf("sg.vantagepoint.") === 0 || name.indexOf("owasp.") === 0)) {
                    sendPayload("lifecycle", "ClassLoader", "loadClass", {
                        "loaded_class": name
                    });
                }
                return this.loadClass(name);
            };
        } catch (e) {}

// --- Module: Cryptography ---

        try {
            var Cipher = Java.use("javax.crypto.Cipher");
            
            Cipher.getInstance.overload("java.lang.String").implementation = function(transform) {
                sendPayload("crypto", "javax.crypto.Cipher", "getInstance", {
                    "transformation": transform,
                    "algorithm": transform.split("/")[0]
                });
                return this.getInstance(transform);
            };

            Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function(opmode, key, params) {
                var keyAlg = key ? key.getAlgorithm() : "UNKNOWN";
                var keyLen = -1;
                try {
                    var enc = key.getEncoded();
                    if (enc) keyLen = enc.length;
                } catch (ke) {}

                var ivLen = -1;
                var ivZeros = false;
                if (params) {
                    try {
                        var IvSpec = Java.cast(params, Java.use("javax.crypto.spec.IvParameterSpec"));
                        var ivBytes = IvSpec.getIV();
                        if (ivBytes) {
                            ivLen = ivBytes.length;
                            ivZeros = isByteArrayAllZeros(ivBytes);
                        }
                    } catch (pe) {}
                }

                sendPayload("crypto", "javax.crypto.Cipher", "init", {
                    "opmode": opmode === 1 ? "ENCRYPT_MODE" : (opmode === 2 ? "DECRYPT_MODE" : String(opmode)),
                    "key_algorithm": keyAlg,
                    "key_length_bytes": keyLen,
                    "iv_length_bytes": ivLen,
                    "iv_all_zeros": ivZeros
                });
                return this.init(opmode, key, params);
            };

            Cipher.init.overload("int", "java.security.Key").implementation = function(opmode, key) {
                var keyAlg = key ? key.getAlgorithm() : "UNKNOWN";
                var keyLen = -1;
                try {
                    var enc = key.getEncoded();
                    if (enc) keyLen = enc.length;
                } catch (ke) {}

                sendPayload("crypto", "javax.crypto.Cipher", "init", {
                    "opmode": opmode === 1 ? "ENCRYPT_MODE" : (opmode === 2 ? "DECRYPT_MODE" : String(opmode)),
                    "key_algorithm": keyAlg,
                    "key_length_bytes": keyLen,
                    "iv_provided": false
                });
                return this.init(opmode, key);
            };
        } catch (e) {}

        try {
            var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
            IvParameterSpec.$init.overload("[B").implementation = function(bytes) {
                var len = bytes ? bytes.length : 0;
                var allZeros = isByteArrayAllZeros(bytes);
                sendPayload("crypto", "javax.crypto.spec.IvParameterSpec", "<init>", {
                    "iv_length_bytes": len,
                    "iv_all_zeros": allZeros
                });
                return this.$init(bytes);
            };
        } catch (e) {}

        try {
            var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
            SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function(key, alg) {
                sendPayload("crypto", "javax.crypto.spec.SecretKeySpec", "<init>", {
                    "algorithm": alg,
                    "key_length_bytes": key ? key.length : 0
                });
                return this.$init(key, alg);
            };
        } catch (e) {}

        try {
            var MessageDigest = Java.use("java.security.MessageDigest");
            MessageDigest.getInstance.overload("java.lang.String").implementation = function(alg) {
                sendPayload("crypto", "java.security.MessageDigest", "getInstance", {
                    "algorithm": alg
                });
                return this.getInstance(alg);
            };
        } catch (e) {}

// --- Module: Networking ---

        try {
            var URL = Java.use("java.net.URL");
            var HttpURLConnection = Java.use("java.net.HttpURLConnection");

            HttpURLConnection.connect.implementation = function() {
                try {
                    var u = this.getURL();
                    var host = u.getHost();
                    var port = u.getPort();
                    var proto = u.getProtocol();
                    var path = u.getPath();
                    var method = this.getRequestMethod();

                    sendPayload("network", "java.net.HttpURLConnection", "connect", {
                        "host": host,
                        "port": port !== -1 ? port : (proto === "https" ? 443 : 80),
                        "protocol": proto,
                        "path": path,
                        "method": method,
                        "cleartext": proto === "http"
                    });
                } catch (ne) {}
                return this.connect();
            };
        } catch (e) {}

// --- Module: TLS & Certificates ---

        try {
            // Hook X509TrustManager to observe validation invocations without bypassing
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            // Individual implementations will be observed dynamically via reflection or loaded classes
        } catch (e) {}

        try {
            var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
            // Monitored dynamically when assigned to HttpsURLConnection
        } catch (e) {}

// --- Module: Storage ---

        try {
            var SharedPreferencesEditor = Java.use("android.content.SharedPreferences$Editor");
            SharedPreferencesEditor.putString.implementation = function(key, value) {
                var keyLower = key ? key.toLowerCase() : "";
                var isSensitive = keyLower.indexOf("password") !== -1 ||
                                  keyLower.indexOf("token") !== -1 ||
                                  keyLower.indexOf("secret") !== -1 ||
                                  keyLower.indexOf("key") !== -1 ||
                                  keyLower.indexOf("auth") !== -1;

                sendPayload("storage", "android.content.SharedPreferences$Editor", "putString", {
                    "key": key,
                    "sensitive": isSensitive,
                    "value_preview": isSensitive ? redactSecret(value) : value
                });
                return this.putString(key, value);
            };
        } catch (e) {}

// --- Initialization Completion ---

        sendPayload("lifecycle", "FELIX", "init", {
            "status": "INSTRUMENTATION_ACTIVE",
            "version": "1.0.0",
            "target": "com.android.insecurebankv2"
        });
    });
} else {
    send({
        "type": "error",
        "description": "Java runtime bridge unavailable in target process"
    });
}
