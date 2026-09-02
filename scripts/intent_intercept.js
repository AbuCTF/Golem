/*
 * Intent interceptor — logs startActivity, sendBroadcast, startService,
 * and ContentProvider queries. Maps the app's IPC surface.
 */

Java.perform(function () {
    var Intent = Java.use("android.content.Intent");
    var Uri = Java.use("android.net.Uri");

    function _intentToDict(intent) {
        var d = {};
        try { d.action = intent.getAction(); } catch (e) {}
        try {
            var data = intent.getData();
            if (data) d.data = data.toString();
        } catch (e) {}
        try {
            var component = intent.getComponent();
            if (component) d.component = component.flattenToString();
        } catch (e) {}
        try {
            var categories = intent.getCategories();
            if (categories) {
                var cats = [];
                var it = categories.iterator();
                while (it.hasNext()) cats.push(it.next());
                d.categories = cats;
            }
        } catch (e) {}
        try {
            var extras = intent.getExtras();
            if (extras) {
                var keys = extras.keySet();
                var extrasObj = {};
                var it = keys.iterator();
                while (it.hasNext()) {
                    var key = it.next();
                    try {
                        var val = extras.get(key);
                        extrasObj[key] = val ? val.toString().substring(0, 200) : null;
                    } catch (e) {
                        extrasObj[key] = "(unreadable)";
                    }
                }
                d.extras = extrasObj;
            }
        } catch (e) {}
        try { d.flags = "0x" + (intent.getFlags() >>> 0).toString(16); } catch (e) {}
        try { d.type = intent.getType(); } catch (e) {}
        return d;
    }

    // 1. startActivity
    try {
        var Activity = Java.use("android.app.Activity");
        Activity.startActivity.overload("android.content.Intent").implementation = function (intent) {
            send({ type: "intent", op: "startActivity", intent: _intentToDict(intent) });
            return this.startActivity(intent);
        };
        Activity.startActivityForResult.overload("android.content.Intent", "int").implementation = function (intent, reqCode) {
            send({ type: "intent", op: "startActivityForResult", intent: _intentToDict(intent), requestCode: reqCode });
            return this.startActivityForResult(intent, reqCode);
        };
    } catch (e) {}

    // 2. sendBroadcast
    try {
        var ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.sendBroadcast.overload("android.content.Intent").implementation = function (intent) {
            send({ type: "intent", op: "sendBroadcast", intent: _intentToDict(intent) });
            return this.sendBroadcast(intent);
        };
    } catch (e) {}

    // 3. startService
    try {
        var ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.startService.overload("android.content.Intent").implementation = function (intent) {
            send({ type: "intent", op: "startService", intent: _intentToDict(intent) });
            return this.startService(intent);
        };
    } catch (e) {}

    // 4. ContentResolver.query — track content provider access
    try {
        var ContentResolver = Java.use("android.content.ContentResolver");
        ContentResolver.query.overload(
            "android.net.Uri", "[Ljava.lang.String;",
            "java.lang.String", "[Ljava.lang.String;",
            "java.lang.String"
        ).implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
            send({
                type: "intent",
                op: "contentResolver.query",
                uri: uri.toString(),
                selection: selection,
            });
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
    } catch (e) {}

    // 5. Deep link / scheme handling
    try {
        var Intent = Java.use("android.content.Intent");
        Intent.setData.implementation = function (uri) {
            if (uri) {
                var scheme = uri.getScheme();
                if (scheme && scheme !== "content" && scheme !== "file" && scheme !== "android-app") {
                    send({
                        type: "intent",
                        op: "setData_deeplink",
                        uri: uri.toString(),
                        scheme: scheme,
                    });
                }
            }
            return this.setData(uri);
        };
    } catch (e) {}

    send({ type: "status", script: "intent_intercept", status: "loaded" });
});
