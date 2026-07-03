/*
 * ssl-unpin — reusable SSL pinning / trust bypass for HTTPS interception.
 * Loaded via frida_run_preset(session_id, "ssl-unpin"). Covers the common
 * Android stacks: system X509TrustManager / Conscrypt TrustManagerImpl,
 * OkHttp3 CertificatePinner, HostnameVerifier, and WebView.
 * Reports what it hooked via send() -> frida_read_messages.
 */
Java.perform(function () {
    function log(m) { try { send("[ssl-unpin] " + m); } catch (e) {} }

    // 1) Conscrypt / platform TrustManagerImpl (Android N+): return empty chain
    try {
        var TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TMI.checkTrustedRecursive.implementation = function () {
            return Java.use("java.util.ArrayList").$new();
        };
        log("hooked TrustManagerImpl.checkTrustedRecursive");
    } catch (e) {}
    try {
        var TMI2 = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TMI2.verifyChain.implementation = function (untrusted) { return untrusted; };
        log("hooked TrustManagerImpl.verifyChain");
    } catch (e) {}

    // 2) Custom X509TrustManager via SSLContext.init
    try {
        var X509TM = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var TrustManager = Java.registerClass({
            name: "org.mcp.TrustAll",
            implements: [X509TM],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var init = SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom");
        init.implementation = function (km, tm, sr) {
            init.call(this, km, [TrustManager.$new()], sr);
        };
        log("hooked SSLContext.init (TrustManager override)");
    } catch (e) {}

    // 3) OkHttp3 CertificatePinner
    try {
        var CP = Java.use("okhttp3.CertificatePinner");
        CP.check.overload("java.lang.String", "java.util.List").implementation =
            function () { return; };
        try {
            CP.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;")
                .implementation = function () { return; };
        } catch (e) {}
        log("hooked okhttp3.CertificatePinner.check");
    } catch (e) {}

    // 4) HostnameVerifier
    try {
        var HNV = Java.use("javax.net.ssl.HttpsURLConnection");
        HNV.setDefaultHostnameVerifier.implementation = function () { return; };
        HNV.setHostnameVerifier.implementation = function () { return; };
        log("neutralised HostnameVerifier setters");
    } catch (e) {}

    // 5) WebView certificate errors
    try {
        var WVC = Java.use("android.webkit.WebViewClient");
        WVC.onReceivedSslError.implementation = function (view, handler, error) {
            try { handler.proceed(); } catch (e) {}
        };
        log("hooked WebViewClient.onReceivedSslError -> proceed");
    } catch (e) {}

    log("done");
});
