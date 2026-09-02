/*
 * WebView interceptor — logs JS bridge interfaces, URL loads, and postMessage.
 * Critical for hybrid app testing (WebView bridge hijack, XSS-to-RCE).
 */

Java.perform(function () {
    // 1. addJavascriptInterface — log bridge name + methods
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.addJavascriptInterface.implementation = function (obj, name) {
            var methods = [];
            var cls = obj.getClass();
            var declaredMethods = cls.getDeclaredMethods();
            for (var i = 0; i < declaredMethods.length; i++) {
                var m = declaredMethods[i];
                var annos = m.getAnnotations();
                var isExposed = false;
                for (var j = 0; j < annos.length; j++) {
                    if (annos[j].toString().indexOf("JavascriptInterface") !== -1) {
                        isExposed = true;
                        break;
                    }
                }
                if (isExposed) {
                    methods.push(m.getName());
                }
            }
            send({
                type: "webview",
                op: "addJavascriptInterface",
                bridge_name: name,
                class: cls.getName(),
                exposed_methods: methods,
                stack: _shortStack(),
            });
            return this.addJavascriptInterface(obj, name);
        };
        send({ type: "hook", target: "WebView.addJavascriptInterface", status: "monitoring" });
    } catch (e) {}

    // 2. loadUrl — track all URL loads and javascript: calls
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
            send({
                type: "webview",
                op: "loadUrl",
                url: url.substring(0, 2000),
                is_javascript: url.indexOf("javascript:") === 0,
            });
            return this.loadUrl(url);
        };

        WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function (url, headers) {
            var hdrs = {};
            if (headers) {
                var it = headers.entrySet().iterator();
                while (it.hasNext()) {
                    var entry = it.next();
                    hdrs[entry.getKey()] = entry.getValue();
                }
            }
            send({
                type: "webview",
                op: "loadUrl",
                url: url.substring(0, 2000),
                headers: hdrs,
            });
            return this.loadUrl(url, headers);
        };
    } catch (e) {}

    // 3. loadDataWithBaseURL
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadDataWithBaseURL.implementation = function (baseUrl, data, mimeType, encoding, historyUrl) {
            send({
                type: "webview",
                op: "loadDataWithBaseURL",
                baseUrl: baseUrl,
                mimeType: mimeType,
                data_preview: data ? data.substring(0, 500) : null,
            });
            return this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
        };
    } catch (e) {}

    // 4. evaluateJavascript
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.evaluateJavascript.implementation = function (script, callback) {
            send({
                type: "webview",
                op: "evaluateJavascript",
                script_preview: script.substring(0, 1000),
            });
            return this.evaluateJavascript(script, callback);
        };
    } catch (e) {}

    // 5. WebViewClient.shouldOverrideUrlLoading — track navigation decisions
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.shouldOverrideUrlLoading.overload("android.webkit.WebView", "java.lang.String").implementation = function (view, url) {
            var result = this.shouldOverrideUrlLoading(view, url);
            send({
                type: "webview",
                op: "shouldOverrideUrlLoading",
                url: url.substring(0, 2000),
                overridden: result,
            });
            return result;
        };
    } catch (e) {}

    // 6. WebSettings — check dangerous settings
    try {
        var WebSettings = Java.use("android.webkit.WebSettings");
        var origSetJSEnabled = WebSettings.setJavaScriptEnabled;
        origSetJSEnabled.implementation = function (enabled) {
            send({ type: "webview", op: "setJavaScriptEnabled", enabled: enabled });
            return origSetJSEnabled.call(this, enabled);
        };
        var origSetAllowFile = WebSettings.setAllowFileAccess;
        origSetAllowFile.implementation = function (allow) {
            send({ type: "webview", op: "setAllowFileAccess", allow: allow });
            return origSetAllowFile.call(this, allow);
        };
        var origSetAllowUniversal = WebSettings.setAllowUniversalAccessFromFileURLs;
        origSetAllowUniversal.implementation = function (allow) {
            if (allow) {
                send({ type: "webview", op: "DANGEROUS_setAllowUniversalAccessFromFileURLs", allow: true });
            }
            return origSetAllowUniversal.call(this, allow);
        };
    } catch (e) {}

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

    send({ type: "status", script: "webview_dump", status: "loaded" });
});
