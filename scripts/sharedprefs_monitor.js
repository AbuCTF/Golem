/*
 * SharedPreferences monitor — logs reads and writes to SharedPreferences.
 * Finds hardcoded tokens, auth state, feature flags, and sensitive data stored insecurely.
 */

Java.perform(function () {
    // SharedPreferencesImpl — the actual implementation class
    try {
        var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");

        // getString
        SharedPreferencesImpl.getString.implementation = function (key, defValue) {
            var result = this.getString(key, defValue);
            if (_isInteresting(key, result)) {
                send({
                    type: "sharedprefs",
                    op: "getString",
                    file: this.mFile.value.getName(),
                    key: key,
                    value: result ? result.substring(0, 500) : null,
                });
            }
            return result;
        };

        // getInt
        SharedPreferencesImpl.getInt.implementation = function (key, defValue) {
            var result = this.getInt(key, defValue);
            if (_isInteresting(key, null)) {
                send({
                    type: "sharedprefs",
                    op: "getInt",
                    file: this.mFile.value.getName(),
                    key: key,
                    value: result,
                });
            }
            return result;
        };

        // getBoolean
        SharedPreferencesImpl.getBoolean.implementation = function (key, defValue) {
            var result = this.getBoolean(key, defValue);
            if (_isInteresting(key, null)) {
                send({
                    type: "sharedprefs",
                    op: "getBoolean",
                    file: this.mFile.value.getName(),
                    key: key,
                    value: result,
                });
            }
            return result;
        };

        send({ type: "hook", target: "SharedPreferencesImpl.get*", status: "monitoring" });
    } catch (e) {}

    // Editor — track writes
    try {
        var Editor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");

        Editor.putString.implementation = function (key, value) {
            send({
                type: "sharedprefs",
                op: "putString",
                key: key,
                value: value ? value.substring(0, 500) : null,
            });
            return this.putString(key, value);
        };

        Editor.putBoolean.implementation = function (key, value) {
            if (_isInteresting(key, null)) {
                send({
                    type: "sharedprefs",
                    op: "putBoolean",
                    key: key,
                    value: value,
                });
            }
            return this.putBoolean(key, value);
        };

        Editor.putInt.implementation = function (key, value) {
            if (_isInteresting(key, null)) {
                send({
                    type: "sharedprefs",
                    op: "putInt",
                    key: key,
                    value: value,
                });
            }
            return this.putInt(key, value);
        };

        Editor.remove.implementation = function (key) {
            send({
                type: "sharedprefs",
                op: "remove",
                key: key,
            });
            return this.remove(key);
        };

        send({ type: "hook", target: "SharedPreferencesImpl$EditorImpl.put*", status: "monitoring" });
    } catch (e) {}

    var INTERESTING_KEYS = [
        "token", "auth", "session", "cookie", "password", "secret",
        "key", "api", "jwt", "bearer", "refresh", "access",
        "user", "email", "phone", "account", "login", "credential",
        "flag", "feature", "debug", "admin", "premium", "pro",
        "pin", "otp", "2fa", "mfa",
    ];

    function _isInteresting(key, value) {
        if (!key) return false;
        var lower = key.toLowerCase();
        for (var i = 0; i < INTERESTING_KEYS.length; i++) {
            if (lower.indexOf(INTERESTING_KEYS[i]) !== -1) return true;
        }
        if (value && typeof value === "string") {
            if (value.length > 20 && /^[A-Za-z0-9+/=_-]+$/.test(value)) return true;
            if (value.indexOf("eyJ") === 0) return true; // JWT
        }
        return false;
    }

    send({ type: "status", script: "sharedprefs_monitor", status: "loaded" });
});
