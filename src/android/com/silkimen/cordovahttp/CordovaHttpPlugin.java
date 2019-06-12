package com.silkimen.cordovahttp;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.security.cert.CertificateFactory;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.SecureRandom;
import java.security.cert.Certificate;

import java.util.ArrayList;
import java.util.Enumeration;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import com.silkimen.http.HostnameVerifierFactory;
import com.silkimen.http.TLSSocketFactory;
import com.silkimen.http.TrustManagersFactory;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.content.res.AssetManager;
import android.util.Log;

public class CordovaHttpPlugin extends CordovaPlugin {
  private static final String TAG = "Cordova-Plugin-HTTP";

  private final TrustManagersFactory trustManagersFactory = new TrustManagersFactory();
  private final HostnameVerifierFactory hostnameVerifierFactory = new HostnameVerifierFactory();

  private boolean followRedirects = true;
  private SSLSocketFactory customSSLSocketFactory;
  private HostnameVerifier customHostnameVerifier;

  @Override
  public void initialize(CordovaInterface cordova, CordovaWebView webView) {
    super.initialize(cordova, webView);

    try {
      this.customSSLSocketFactory = this.createSocketFactory(
          this.trustManagersFactory.getPinnedTrustManagers(this.getCertsFromKeyStore("AndroidCAStore")));
    } catch (Exception e) {
      Log.e(TAG, "An error occured while loading system's CA certificates", e);
    }
  }

  @Override
  public boolean execute(String action, final JSONArray args, final CallbackContext callbackContext)
      throws JSONException {

    if (action == null) {
      return false;
    }

    if ("get".equals(action)) {
      return this.executeHttpRequestWithParams(action, args, callbackContext);
    } else if ("head".equals(action)) {
      return this.executeHttpRequestWithParams(action, args, callbackContext);
    } else if ("delete".equals(action)) {
      return this.executeHttpRequestWithParams(action, args, callbackContext);
    } else if ("post".equals(action)) {
      return this.executeHttpRequestWithData(action, args, callbackContext);
    } else if ("put".equals(action)) {
      return this.executeHttpRequestWithData(action, args, callbackContext);
    } else if ("patch".equals(action)) {
      return this.executeHttpRequestWithData(action, args, callbackContext);
    } else if ("uploadFile".equals(action)) {
      return this.uploadFile(args, callbackContext);
    } else if ("downloadFile".equals(action)) {
      return this.downloadFile(args, callbackContext);
    } else if ("setServerTrustMode".equals(action)) {
      return this.setServerTrustMode(args, callbackContext);
    } else if ("disableRedirect".equals(action)) {
      return this.disableRedirect(args, callbackContext);
    } else {
      return false;
    }
  }
  
 private boolean executeHttpRequestWithParams(final String method, final JSONArray args,
      final CallbackContext callbackContext) throws JSONException {

    String url = args.getString(0);
    JSONObject params = args.getJSONObject(1);
    JSONObject headers = args.getJSONObject(2);
    int timeout = args.getInt(3) * 1000;

    CordovaHttpOperation request = new CordovaHttpOperation(method.toUpperCase(), url, params, headers, timeout,
        this.followRedirects, this.customSSLSocketFactory, this.customHostnameVerifier, callbackContext);

    cordova.getThreadPool().execute(request);

    return true;
  }

  private boolean executeHttpRequestWithData(final String method, final JSONArray args,
      final CallbackContext callbackContext) throws JSONException {

    String url = args.getString(0);
    Object data = args.get(1);
    String serializer = args.getString(2);
    JSONObject headers = args.getJSONObject(3);
    int timeout = args.getInt(4) * 1000;

    CordovaHttpOperation request = new CordovaHttpOperation(method.toUpperCase(), url, serializer, data, headers,
        timeout, this.followRedirects, this.customSSLSocketFactory, this.customHostnameVerifier, callbackContext);

    cordova.getThreadPool().execute(request);

    return true;
  }

  private boolean uploadFile(final JSONArray args, final CallbackContext callbackContext) throws JSONException {
    String url = args.getString(0);
    JSONObject params = args.getJSONObject(1);
    JSONObject headers = args.getJSONObject(2);
    String filePath = args.getString(3);
    String uploadName = args.getString(4);
    int timeout = args.getInt(5) * 1000;

    CordovaHttpUpload upload = new CordovaHttpUpload(url, params, headers, filePath, uploadName, timeout,
        this.followRedirects, this.customSSLSocketFactory, this.customHostnameVerifier, callbackContext);

    cordova.getThreadPool().execute(upload);

    return true;
  }

  private boolean downloadFile(final JSONArray args, final CallbackContext callbackContext) throws JSONException {
    String url = args.getString(0);
    JSONObject params = args.getJSONObject(1);
    JSONObject headers = args.getJSONObject(2);
    String filePath = args.getString(3);
    int timeout = args.getInt(4) * 1000;

    CordovaHttpDownload download = new CordovaHttpDownload(url, params, headers, filePath, timeout,
        this.followRedirects, this.customSSLSocketFactory, this.customHostnameVerifier, callbackContext);

    cordova.getThreadPool().execute(download);

    return true;
  }
  
  private boolean setServerTrustMode(final JSONArray args, final CallbackContext callbackContext) throws JSONException {
    CordovaServerTrust runnable = new CordovaServerTrust(args.getString(0), this.cordova.getActivity(),
        this.tlsConfiguration, callbackContext);
    cordova.getThreadPool().execute(runnable);
    return true;
  }

  private boolean setSSLCertMode(final JSONArray args, final CallbackContext callbackContext) {
    try {
      switch (args.getString(0)) {
      case "legacy":
        this.customHostnameVerifier = null;
        this.customSSLSocketFactory = null;
        break;
      case "nocheck":
        this.customHostnameVerifier = this.hostnameVerifierFactory.getNoOpVerifier();
        this.customSSLSocketFactory = this.createSocketFactory(this.trustManagersFactory.getNoopTrustManagers());
        break;
      case "pinned":
        this.customHostnameVerifier = null;
        this.customSSLSocketFactory = this.createSocketFactory(
            this.trustManagersFactory.getPinnedTrustManagers(this.getCertsFromBundle("www/certificates")));
        break;
      default:
        this.customHostnameVerifier = null;
        this.customSSLSocketFactory = this.createSocketFactory(
            this.trustManagersFactory.getPinnedTrustManagers(this.getCertsFromKeyStore("AndroidCAStore")));
        break;
      }

      callbackContext.success();
    } catch (Exception e) {
      Log.e(TAG, "An error occured while configuring SSL cert mode", e);
      callbackContext.error("An error occured while configuring SSL cert mode");
    }

    return true;
  }

  private boolean disableRedirect(final JSONArray args, final CallbackContext callbackContext) throws JSONException {
    this.followRedirects = !args.getBoolean(0);

    callbackContext.success();

    return true;
  }

  private ArrayList<Certificate> getCertsFromKeyStore(String storeType) throws GeneralSecurityException, IOException {
    ArrayList<Certificate> certList = new ArrayList<Certificate>();
    KeyStore keyStore = KeyStore.getInstance(storeType);
    keyStore.load(null);

    Enumeration<String> aliases = keyStore.aliases();

    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      TrustedCertificateEntry certEntry = (TrustedCertificateEntry) keyStore.getEntry(alias, null);
      Certificate cert = certEntry.getTrustedCertificate();
      certList.add(cert);
    }

    return certList;
  }

  private ArrayList<Certificate> getCertsFromBundle(String path) throws GeneralSecurityException, IOException {
    AssetManager assetManager = cordova.getActivity().getAssets();
    String[] files = assetManager.list(path);
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    ArrayList<Certificate> certList = new ArrayList<Certificate>();

    for (int i = 0; i < files.length; i++) {
      int index = files[i].lastIndexOf('.');

      if (index == -1 || !files[i].substring(index).equals(".cer")) {
        continue;
      }

      certList.add(cf.generateCertificate(assetManager.open(path + "/" + files[i])));
    }

    return certList;
  }

  private SSLSocketFactory createSocketFactory(TrustManager[] trustManagers) throws IOException {
    try {
      SSLContext context = SSLContext.getInstance("TLS");

      /* @TODO implement custom KeyManager */
      context.init(null, trustManagers, new SecureRandom());

      if (android.os.Build.VERSION.SDK_INT < 20) {
        return new TLSSocketFactory(context);
      } else {
        return context.getSocketFactory();
      }
    } catch (GeneralSecurityException e) {
      IOException ioException = new IOException("Security exception occured while configuring SSL context");
      ioException.initCause(e);
      throw ioException;
    }
  }
}
