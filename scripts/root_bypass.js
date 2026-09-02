/*
 * Root detection bypass — hooks common root checks in RootBeer, SafetyNet,
 * and manual su/Magisk/Superuser checks.
 */

Java.perform(function () {
    var String = Java.use("java.lang.String");

    // su binary paths that root detectors look for
    var SU_PATHS = [
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/system/su", "/system/bin/.ext/.su",
        "/system/usr/we-need-root/su-backup",
        "/data/local/xbin/su", "/data/local/bin/su", "/data/local/su",
    ];

    var ROOT_PACKAGES = [
        "com.noshufou.android.su", "com.thirdparty.superuser",
        "eu.chainfire.supersu", "com.koushikdutta.superuser",
        "com.zachspong.temprootremovejb", "com.ramdroid.appquarantine",
        "com.topjohnwu.magisk", "me.phh.superuser",
    ];

    var ROOT_FILES = [
        "/system/app/Superuser.apk", "/system/etc/init.d/99telekinesis",
        "/system/xbin/daemonsu", "/system/app/SuperSU",
        "/data/adb/magisk", "/sbin/.magisk",
    ];

    // 1. File.exists — hide root files
    try {
        var File = Java.use("java.io.File");
        var origExists = File.exists;
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            for (var i = 0; i < SU_PATHS.length; i++) {
                if (path === SU_PATHS[i]) return false;
            }
            for (var i = 0; i < ROOT_FILES.length; i++) {
                if (path === ROOT_FILES[i]) return false;
            }
            if (path.indexOf("magisk") !== -1 || path.indexOf("supersu") !== -1) return false;
            return origExists.call(this);
        };
        send({ type: "hook", target: "File.exists", status: "filtering root paths" });
    } catch (e) {}

    // 2. Runtime.exec — block su execution attempts
    try {
        var Runtime = Java.use("java.lang.Runtime");
        var origExec = Runtime.exec.overload("java.lang.String");
        origExec.implementation = function (cmd) {
            if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
                send({ type: "hook", target: "Runtime.exec", blocked: cmd });
                throw Java.use("java.io.IOException").$new("Permission denied");
            }
            return origExec.call(this, cmd);
        };
    } catch (e) {}

    // 3. Runtime.exec(String[]) variant
    try {
        var Runtime = Java.use("java.lang.Runtime");
        var origExecArr = Runtime.exec.overload("[Ljava.lang.String;");
        origExecArr.implementation = function (cmds) {
            var joined = "";
            for (var i = 0; i < cmds.length; i++) joined += cmds[i] + " ";
            if (joined.indexOf("su") !== -1 || joined.indexOf("which") !== -1) {
                send({ type: "hook", target: "Runtime.exec[]", blocked: joined.trim() });
                throw Java.use("java.io.IOException").$new("Permission denied");
            }
            return origExecArr.call(this, cmds);
        };
    } catch (e) {}

    // 4. PackageManager — hide root packages
    try {
        var PM = Java.use("android.app.ApplicationPackageManager");
        var origGetPackageInfo = PM.getPackageInfo.overload("java.lang.String", "int");
        origGetPackageInfo.implementation = function (pkg, flags) {
            for (var i = 0; i < ROOT_PACKAGES.length; i++) {
                if (pkg === ROOT_PACKAGES[i]) {
                    send({ type: "hook", target: "PackageManager.getPackageInfo", blocked: pkg });
                    throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkg);
                }
            }
            return origGetPackageInfo.call(this, pkg, flags);
        };
    } catch (e) {}

    // 5. System.getProperty — hide ro.debuggable, ro.secure
    try {
        var System = Java.use("java.lang.System");
        var origGetProp = System.getProperty.overload("java.lang.String");
        origGetProp.implementation = function (key) {
            if (key === "ro.debuggable") return "0";
            if (key === "ro.secure") return "1";
            return origGetProp.call(this, key);
        };
    } catch (e) {}

    // 6. Build.TAGS — hide test-keys
    try {
        var Build = Java.use("android.os.Build");
        Build.TAGS.value = "release-keys";
        send({ type: "hook", target: "Build.TAGS", status: "set to release-keys" });
    } catch (e) {}

    // 7. RootBeer specific
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function () { return false; };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function () { return false; };
        send({ type: "hook", target: "RootBeer", status: "bypassed" });
    } catch (e) {}

    send({ type: "status", script: "root_bypass", status: "loaded" });
});
