/*
 * Crypto monitor — logs encryption/decryption/hashing operations.
 * Useful for finding hardcoded keys, weak algorithms, and crypto misuse.
 */

Java.perform(function () {
    // 1. Cipher — track encrypt/decrypt with algorithm details
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload("[B").implementation = function (input) {
            var result = this.doFinal(input);
            var algo = this.getAlgorithm();
            var mode = this.getBlockMode ? this.getBlockMode() : "?";
            send({
                type: "crypto",
                op: this.getOpmode() === 1 ? "encrypt" : "decrypt",
                algorithm: algo,
                input_len: input.length,
                output_len: result.length,
                input_hex: _bytesToHex(input, 64),
                stack: _shortStack(),
            });
            return result;
        };
        send({ type: "hook", target: "Cipher.doFinal", status: "monitoring" });
    } catch (e) {}

    // 2. SecretKeySpec — log key material
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algo) {
            send({
                type: "crypto",
                op: "key_created",
                algorithm: algo,
                key_len: key.length,
                key_hex: _bytesToHex(key, 64),
                stack: _shortStack(),
            });
            return this.$init(key, algo);
        };
        send({ type: "hook", target: "SecretKeySpec", status: "monitoring" });
    } catch (e) {}

    // 3. MessageDigest — track hashing
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.digest.overload("[B").implementation = function (input) {
            var result = this.digest(input);
            send({
                type: "crypto",
                op: "hash",
                algorithm: this.getAlgorithm(),
                input_len: input.length,
                input_preview: _bytesToUtf8(input, 128),
                hash_hex: _bytesToHex(result, 64),
            });
            return result;
        };
    } catch (e) {}

    // 4. Mac — HMAC operations
    try {
        var Mac = Java.use("javax.crypto.Mac");
        Mac.doFinal.overload("[B").implementation = function (input) {
            var result = this.doFinal(input);
            send({
                type: "crypto",
                op: "hmac",
                algorithm: this.getAlgorithm(),
                input_preview: _bytesToUtf8(input, 128),
                mac_hex: _bytesToHex(result, 64),
            });
            return result;
        };
    } catch (e) {}

    // 5. IvParameterSpec — track IVs (static IVs = vuln)
    try {
        var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        IvParameterSpec.$init.overload("[B").implementation = function (iv) {
            send({
                type: "crypto",
                op: "iv_created",
                iv_hex: _bytesToHex(iv, 32),
                stack: _shortStack(),
            });
            return this.$init(iv);
        };
    } catch (e) {}

    function _bytesToHex(arr, maxLen) {
        var hex = "";
        var len = Math.min(arr.length, maxLen || 64);
        for (var i = 0; i < len; i++) {
            var b = (arr[i] & 0xff).toString(16);
            hex += b.length === 1 ? "0" + b : b;
        }
        if (arr.length > len) hex += "...";
        return hex;
    }

    function _bytesToUtf8(arr, maxLen) {
        try {
            var s = Java.use("java.lang.String").$new(arr, "UTF-8");
            if (s.length() > maxLen) return s.substring(0, maxLen) + "...";
            return s;
        } catch (e) {
            return "(binary)";
        }
    }

    function _shortStack() {
        var stack = Java.use("java.lang.Thread").currentThread().getStackTrace();
        var frames = [];
        for (var i = 3; i < Math.min(stack.length, 8); i++) {
            var f = stack[i].toString();
            if (f.indexOf("frida") === -1 && f.indexOf("dalvik") === -1) {
                frames.push(f);
            }
        }
        return frames.join(" < ");
    }

    send({ type: "status", script: "crypto_monitor", status: "loaded" });
});
