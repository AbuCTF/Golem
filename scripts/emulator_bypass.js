/*
 * Emulator detection bypass — hides emulator artifacts so apps
 * think they're running on a physical device.
 */

Java.perform(function () {
    // 1. Build properties — override emulator fingerprints
    try {
        var Build = Java.use("android.os.Build");
        Build.FINGERPRINT.value = "google/raven/raven:14/AP2A.240905.003/12231197:user/release-keys";
        Build.MODEL.value = "Pixel 6 Pro";
        Build.MANUFACTURER.value = "Google";
        Build.BRAND.value = "google";
        Build.DEVICE.value = "raven";
        Build.PRODUCT.value = "raven";
        Build.HARDWARE.value = "tensor";
        Build.BOARD.value = "raven";
        Build.HOST.value = "abfarm-release-rbe-2004-00175";
        Build.TAGS.value = "release-keys";
        Build.TYPE.value = "user";
        send({ type: "hook", target: "Build.*", status: "spoofed to Pixel 6 Pro" });
    } catch (e) {}

    // 2. TelephonyManager — hide emulator phone info
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");

        TelephonyManager.getDeviceId.overload().implementation = function () {
            return "358240051111110";
        };
        TelephonyManager.getSubscriberId.overload().implementation = function () {
            return "310260000000000";
        };
        TelephonyManager.getSimSerialNumber.overload().implementation = function () {
            return "89014103211118510720";
        };
        TelephonyManager.getNetworkOperatorName.overload().implementation = function () {
            return "T-Mobile";
        };
        TelephonyManager.getNetworkOperator.overload().implementation = function () {
            return "310260";
        };
        TelephonyManager.getPhoneType.overload().implementation = function () {
            return 1; // GSM
        };
        TelephonyManager.getSimOperator.overload().implementation = function () {
            return "310260";
        };
        send({ type: "hook", target: "TelephonyManager", status: "spoofed" });
    } catch (e) {}

    // 3. SystemProperties — hide qemu/goldfish/ranchu
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        var origGet = SystemProperties.get.overload("java.lang.String");
        origGet.implementation = function (key) {
            if (key === "ro.hardware") return "tensor";
            if (key === "ro.product.model") return "Pixel 6 Pro";
            if (key === "ro.product.brand") return "google";
            if (key === "ro.product.device") return "raven";
            if (key === "ro.product.manufacturer") return "Google";
            if (key === "ro.kernel.qemu") return "0";
            if (key === "ro.kernel.qemu.avd_name") return "";
            if (key === "ro.kernel.androidboot.hardware") return "tensor";
            if (key === "init.svc.qemud") return "";
            if (key === "init.svc.qemu-props") return "";
            if (key === "ro.hardware.chipname") return "exynos990";
            if (key === "gsm.version.baseband") return "g5123b-131072-230609-B-10409834";
            return origGet.call(this, key);
        };

        var origGetDefault = SystemProperties.get.overload("java.lang.String", "java.lang.String");
        origGetDefault.implementation = function (key, def) {
            var result = origGet.call(this, key);
            return result || def;
        };
        send({ type: "hook", target: "SystemProperties", status: "filtering emu props" });
    } catch (e) {}

    // 4. Sensors — apps check for missing accelerometer/gyro
    try {
        var SensorManager = Java.use("android.hardware.SensorManager");
        var origGetDefaultSensor = SensorManager.getDefaultSensor.overload("int");
        var origImpl = origGetDefaultSensor;
        origGetDefaultSensor.implementation = function (type) {
            var sensor = origImpl.call(this, type);
            if (sensor === null) {
                send({ type: "hook", target: "SensorManager.getDefaultSensor", note: "sensor type " + type + " is null (emulator)" });
            }
            return sensor;
        };
    } catch (e) {}

    // 5. File checks — hide emulator-specific files
    try {
        var File = Java.use("java.io.File");
        var origExists = File.exists;
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            var emuFiles = [
                "/dev/socket/qemud", "/dev/qemu_pipe",
                "/system/lib/libc_malloc_debug_qemu.so",
                "/sys/qemu_trace", "/system/bin/qemu-props",
                "/dev/goldfish_pipe",
            ];
            for (var i = 0; i < emuFiles.length; i++) {
                if (path === emuFiles[i]) return false;
            }
            return origExists.call(this);
        };
    } catch (e) {}

    // 6. Settings.Secure.ANDROID_ID — don't return emulator default
    try {
        var Settings = Java.use("android.provider.Settings$Secure");
        var origGetString = Settings.getString.overload("android.content.ContentResolver", "java.lang.String");
        origGetString.implementation = function (cr, name) {
            if (name === "android_id") {
                return "a1b2c3d4e5f6a7b8";
            }
            return origGetString.call(this, cr, name);
        };
    } catch (e) {}

    send({ type: "status", script: "emulator_bypass", status: "loaded" });
});
