package ch.migros.plugin;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.preference.PreferenceManager;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.util.Log;
import android.widget.Toast;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.ICordovaClientCertRequest;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;


@TargetApi(Build.VERSION_CODES.LOLLIPOP)
public class Plugin_CertificateAuthentication extends CordovaPlugin {


    public static final String SP_KEY_ALIAS = "SP_KEY_ALIAS";
    public static final String TAG = "client-cert-auth";

    X509Certificate[] mCertificates;
    PrivateKey mPrivateKey;
    String mAlias;


    @Override
    public Boolean shouldAllowBridgeAccess(String url) {
        Log.d(TAG, "PlugTest 13, shouldAllowBridgeAccess url="+url);
        return super.shouldAllowBridgeAccess(url);
    }


    @TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
    @Override
    public boolean onReceivedClientCertRequest(CordovaWebView view, ICordovaClientCertRequest request) {
        
        if (mCertificates == null || mPrivateKey == null) {
            Log.d(TAG, "onReceivedClientCertRequest -> loadKeys()");
            loadKeys(request);
        } else {
            Log.d(TAG, "onReceivedClientCertRequest -> proceedRequers()");
            proceedRequers(request);
        }
        return true;
    }

    private static s_threadPool=null;
    private static s_cordova=null;

    private void loadKeys(ICordovaClientCertRequest request) {
        s_cordova = cordova;
        s_threadPool = cordova.getThreadPool();

        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(cordova.getActivity());
        final KeyChainAliasCallback callback = new AliasCallback(cordova.getActivity(), request);
        final String alias = sp.getString(SP_KEY_ALIAS, null);

        Log.d(TAG, "loadKeys(), alias="+alias);

        if (alias == null) {
            Log.d(TAG, "call KeyChain.choosePrivateKeyAlias");
            KeyChain.choosePrivateKeyAlias(cordova.getActivity(), callback, new String[]{"RSA"}, null, request.getHost(), request.getPort(), null);
        } else {
            s_threadPool.submit(new Runnable() {
                @Override
                public void run() {
                    Log.d(TAG, "callback.alias for alias="+alias);
                    callback.alias(alias);
                }
            });
        }
    }


    static class AliasCallback implements KeyChainAliasCallback {


        private final SharedPreferences mPreferences;
        private final ICordovaClientCertRequest mRequest;
        private final Context mContext;

        public AliasCallback(Context context, ICordovaClientCertRequest request) {
            Log.d(TAG, "AliasCallback constructor");
            mRequest = request;
            mContext = context;
            mPreferences = PreferenceManager.getDefaultSharedPreferences(mContext);
        }

        @Override
        public void alias(String alias) {
            SharedPreferences.Editor edt = mPreferences.edit();
Log.d(TAG, "AliasCallback.alias: STEP 01");
            try {
Log.d(TAG, "AliasCallback.alias: STEP 02");
                if (alias != null) {
Log.d(TAG, "AliasCallback.alias: STEP 03");
                    Log.d(TAG, "AliasCallback.alias: store cert binding. alias="+alias);
                    edt.putString(SP_KEY_ALIAS, alias);
                    edt.apply();
Log.d(TAG, "AliasCallback.alias: STEP 04");
                    PrivateKey pk = KeyChain.getPrivateKey(mContext, alias);
Log.d(TAG, "AliasCallback.alias: STEP 05");                    
                    X509Certificate[] cert = KeyChain.getCertificateChain(mContext, alias);
Log.d(TAG, "AliasCallback.alias: STEP 06");                    
                    //----TEST----
                    Log.d(TAG, "cert.length(): "+cert.length);

                    for (X509Certificate c:cert) {
                        Log.d(TAG, "getSerialNumber: "+c.getSerialNumber());
                        Log.d(TAG, "getNotBefore: "+c.getNotBefore());
                        Log.d(TAG, "getNotAfter: "+c.getNotAfter());
                        Log.d(TAG, "getSubjectDN().getName(): "+c.getSubjectDN().getName());
                        Log.d(TAG, "getIssuerX500Principal().getName(): "+c.getIssuerX500Principal().getName());
Log.d(TAG, "AliasCallback.alias: STEP 07");
                        try {
                            Log.d(TAG, "AliasCallback.alias: STEP 08");
                            c.checkValidity();
                            Log.d(TAG, "AliasCallback.alias: STEP 09");
                        } catch (Exception e) {
                            Log.d(TAG, "check validity="+ e.toString());
                        }
                    }
                    //-----ENDE------
                    if (cert.length>0) {
                        Log.d(TAG, "AliasCallback.alias: STEP 10");
                        mRequest.proceed(pk, cert);
                    } else {
                        Log.d(TAG, "AliasCallback.alias: STEP 11");
                        Log.d(TAG, "AliasCallback.alias: remove cert binding. alias="+alias);
                        edt.putString(SP_KEY_ALIAS, null);
                        edt.apply();
                        Log.d(TAG, "AliasCallback.alias: STEP 12");
                        mRequest.proceed(null, null);
                    }
                } else {
                    Log.d(TAG, "AliasCallback.alias: STEP 13");
                    Log.d(TAG, "AliasCallback.alias: remove cert binding. alias="+alias);
                    edt.putString(SP_KEY_ALIAS, null);
                    edt.apply();
                    mRequest.proceed(null, null);
                }
            } catch (KeyChainException e) {
                Log.d(TAG, "AliasCallback.alias: STEP 14");
                String errorText = "AliasCallback.alias: Failed to load certificates";
              //  Toast.makeText(mContext, errorText, Toast.LENGTH_SHORT).show();
                Log.e(TAG, errorText + " "+ e.toString(), e);
                Log.d(TAG, "remove cert binding. alias="+alias);
                edt.putString(SP_KEY_ALIAS, null);
                edt.apply();
                certError(alias);
            } catch (InterruptedException e) {
                Log.d(TAG, "AliasCallback.alias: STEP 15");
                String errorText = "AliasCallback.alias: InterruptedException while loading certificates";
              //  Toast.makeText(mContext, errorText, Toast.LENGTH_SHORT).show();
                Log.e(TAG, errorText + " "+ e.toString(), e);
                Log.d(TAG, "remove cert binding. alias="+alias);
                edt.putString(SP_KEY_ALIAS, null);
                edt.apply();
                certError(alias);
            }
        }
        
        public void certError(final String alias) {
            s_cordova.runOnUiThread(new Runnable() {
            public void run() {
                try {
                    Toast.makeText(mContext, "Certificate not accessible. Please conact your System Administrator. App will be terminated now. Alias=" + alias, Toast.LENGTH_LONG).show();
 
                    s_threadPool.submit(new Runnable() {
                        @Override
                        public void run() {
                            try {Thread.sleep(5000);} catch (Exception ex){};
                            System.exit(1);
                        }
                    });

                } catch (Exception ex) {
                    Log.e(TAG, ex.toString(), ex);
                }
                
            }
           });
        }
    }

    

    public void proceedRequers(ICordovaClientCertRequest request) {
Log.d(TAG, "AliasCallback.alias: STEP 16");
        Log.d(TAG, "proceedRequers() mPrivateKey="+mPrivateKey + " mCertificates="+mCertificates);
        request.proceed(mPrivateKey, mCertificates);
    }
}