/*
 * SSL pinning bypass — covers TrustManager, OkHttp, Conscrypt, and network_security_config.
 * Hooks the most common pinning implementations on Android 7+.
 */

Java.perform(function () {
    // 1. TrustManagerImpl — Android's default certificate verifier
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function () {
            return arguments[0]; // return the unverified chain as-is
        };
        send({ type: "hook", target: "TrustManagerImpl.verifyChain", status: "bypassed" });
    } catch (e) {}

    // 2. X509TrustManager — custom implementations
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var TrustManager = Java.registerClass({
            name: "com.golem.TrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () {
                    return [];
                },
            },
        });
    } catch (e) {}

    // 3. SSLContext.init — inject our permissive TrustManager
    try {
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function (km, tm, sr) {
            this.init(km, null, sr);
            send({ type: "hook", target: "SSLContext.init", status: "bypassed" });
        };
    } catch (e) {}

    // 4. OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function () {
            send({ type: "hook", target: "OkHttp3.CertificatePinner.check", status: "bypassed" });
        };
    } catch (e) {}

    // OkHttp3 CertificatePinner$check$okhttp (Kotlin variant)
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner["check$okhttp"].implementation = function () {
            send({ type: "hook", target: "OkHttp3.CertificatePinner.check$okhttp", status: "bypassed" });
        };
    } catch (e) {}

    // 5. Conscrypt / OpenSSLSocketImpl
    try {
        var OpenSSLSocketImpl = Java.use("com.android.org.conscrypt.OpenSSLSocketImpl");
        OpenSSLSocketImpl.verifyCertificateChain.implementation = function () {
            send({ type: "hook", target: "OpenSSLSocketImpl.verifyCertificateChain", status: "bypassed" });
        };
    } catch (e) {}

    // 6. WebViewClient onReceivedSslError — proceed through SSL errors
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            handler.proceed();
            send({ type: "hook", target: "WebViewClient.onReceivedSslError", status: "bypassed" });
        };
    } catch (e) {}

    // 7. network_security_config — disable cleartextTrafficPermitted check
    try {
        var NetworkSecurityConfig = Java.use("android.security.net.config.NetworkSecurityConfig");
        NetworkSecurityConfig.isCleartextTrafficPermitted.implementation = function () {
            return true;
        };
        send({ type: "hook", target: "NetworkSecurityConfig.isCleartextTrafficPermitted", status: "bypassed" });
    } catch (e) {}

    send({ type: "status", script: "ssl_bypass", status: "loaded" });
});
