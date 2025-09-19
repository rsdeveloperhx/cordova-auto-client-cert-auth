package ch.migros.plugin;

import android.annotation.TargetApi;
import android.app.ActivityManager;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.preference.PreferenceManager;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.util.Log;
import android.widget.Toast;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.ICordovaClientCertRequest;
import org.json.JSONArray;
import org.json.JSONException;

import java.security.PrivateKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.ExecutorService;


@TargetApi(Build.VERSION_CODES.LOLLIPOP)
public class Plugin_CertificateAuthentication extends CordovaPlugin {


    public static final String SP_KEY_ALIAS = "SP_KEY_ALIAS";
    public static final String TAG = "client-cert-auth";

    X509Certificate[] mCertificates;
    PrivateKey mPrivateKey;
    String mAlias;

    private static ExecutorService  s_threadPool=null;
    private static CordovaInterface s_cordova=null;

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        s_cordova = cordova;
        s_threadPool = cordova.getThreadPool();
    }

    @Override
    public boolean execute(final String action, final JSONArray data, final CallbackContext callbackContext) throws JSONException {
        if (action.equalsIgnoreCase("clearCertificateBinding")) {
            clearCertificateBinding();
            callbackContext.success();
            return true;
        } else if (action.equalsIgnoreCase("clearCacheAndTerminateApp")) {
            clearCacheAndTerminateApp();
            callbackContext.success();
            return true;
        } else if (action.equalsIgnoreCase("terminateApp")) {
            terminateApp();
            callbackContext.success();
            return true;
        }
        return false;
    }

    private void clearCacheAndTerminateApp() {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                webView.clearCache(true);
                webView.clearHistory();
                boolean result = ((ActivityManager) s_cordova.getContext().getSystemService(Context.ACTIVITY_SERVICE)).clearApplicationUserData();
                terminateApp();
            }
        });

    }

    private static void terminateApp() {
        System.exit(0);
    }

    private static void clearCertificateBinding() {
        SharedPreferences sharedPrefs = PreferenceManager.getDefaultSharedPreferences( s_cordova.getContext() );;
        SharedPreferences.Editor edt = sharedPrefs.edit();
        edt.putString(SP_KEY_ALIAS, null);
        edt.apply();
    }

    /**
     * Convenience Methode für das Starten von Runnables
     * auf dem UI Thread aus Background Threads
     *
     * @param r
     */
    public static void runOnUiThread(Runnable r) {
        //check added@20160907: when the current thread is already the ui thread, do not post but call directly run.
        if (Looper.getMainLooper().getThread() == Thread.currentThread()) {
            r.run();
        } else {
            Handler handler = new Handler(Looper.getMainLooper());
            handler.post(r);
        }
    }
    @Override
    public Boolean shouldAllowBridgeAccess(String url) {
        return super.shouldAllowBridgeAccess(url);
    }


    @TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
    @Override
    public boolean onReceivedClientCertRequest(CordovaWebView view, ICordovaClientCertRequest request) {
        
        if (mCertificates == null || mPrivateKey == null) {
            loadKeys(request);
        } else {
            proceedRequers(request);
        }
        return true;
    }


    private static void loadKeys(ICordovaClientCertRequest request) {


        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(s_cordova.getActivity());
        final KeyChainAliasCallback callback = new AliasCallback(s_cordova.getActivity(), request);
        final String alias = sp.getString(SP_KEY_ALIAS, null);


        if (alias == null)  {
            KeyChain.choosePrivateKeyAlias(s_cordova.getActivity(), callback, new String[]{"RSA"}, null, request.getHost(), request.getPort(), null);
        } else {
            s_threadPool.submit(new Runnable() {
                @Override
                public void run() {
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
            mRequest = request;
            mContext = context;
            mPreferences = PreferenceManager.getDefaultSharedPreferences(mContext);
        }

        @Override
        public void alias(String alias) {
            SharedPreferences.Editor edt = mPreferences.edit();
            try {
                if (alias != null) {
                    PrivateKey pk = KeyChain.getPrivateKey(mContext, alias);
                    X509Certificate[] cert = KeyChain.getCertificateChain(mContext, alias);

                    if (alias!=null && !alias.contains("devicemgl")) {
                        showWarningWrongCert();
                        return;
                    }
                    
                    edt.putString(SP_KEY_ALIAS, alias);
                    edt.apply();

                    for (X509Certificate c:cert) {
                        String name=c.getSubjectDN().getName();
                        if (name.contains("device-mgl-")) {
                            boolean isvalid=false;
                            try {
                                String s=new Date().toString();
                                c.checkValidity();
                                isvalid=true;
                            } catch (CertificateExpiredException silent) {

                            } catch (CertificateNotYetValidException silent) {

                            }
                            if (!isvalid) {
                                clearCertificateBinding();
                                showWarningExpiredCert();
                                return;
                            }
                        }
                        
                        try {
                            c.checkValidity();
                        } catch (Exception e) {
                        }
                    }
                    //-----ENDE------
                    if (cert.length>0) {
                        mRequest.proceed(pk, cert);
                    } else {
                        edt.putString(SP_KEY_ALIAS, null);
                        edt.apply();
                        mRequest.proceed(null, null);
                    }
                } else {
                    edt.putString(SP_KEY_ALIAS, null);
                    edt.apply();
                    showCertificateMustBeSelected();
                }
            } catch (KeyChainException e) {
                String errorText = "AliasCallback.alias: Failed to load certificates";
              //  Toast.makeText(mContext, errorText, Toast.LENGTH_SHORT).show();
                edt.putString(SP_KEY_ALIAS, null);
                edt.apply();
                certError(alias);
            } catch (InterruptedException e) {
                String errorText = "AliasCallback.alias: InterruptedException while loading certificates";
              //  Toast.makeText(mContext, errorText, Toast.LENGTH_SHORT).show();
                edt.putString(SP_KEY_ALIAS, null);
                edt.apply();
                certError(alias);
            }
        }

        private String getMessageText(String ivKey){
            Context context = s_cordova.getActivity().getApplicationContext();
            int lvIdent = context.getResources().getIdentifier(ivKey, "string", context.getPackageName());
            String lMessage = context.getString(lvIdent, context.getPackageName());
            return lMessage;
        }

        private void showWarningExpiredCert() {
            showMessageBox(getMessageText("certtitle"),getMessageText("certmsg3"),true);
        }

        private void showWarningWrongCert() {
            showMessageBox(getMessageText("certtitle"),getMessageText("certmsg2"));
        }

        private void showCertificateMustBeSelected() {
            showMessageBox(getMessageText("certtitle"),getMessageText("certmsg1"));
        }

        private void showMessageBox(String title, String message) {
            showMessageBox(title,message,false);
        }
        private void showMessageBox(String title, String message, final boolean shutdown) {
            // Show the alert dialog on the UI thread
            s_cordova.getActivity().runOnUiThread(() -> {
                AlertDialog.Builder builder = new AlertDialog.Builder(s_cordova.getActivity());
                builder.setTitle(title);
                builder.setMessage(message);
                builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();

                        if (!shutdown)
                            Plugin_CertificateAuthentication.loadKeys(mRequest);
                        else
                            terminateApp();
                    }
                });
                builder.setCancelable(false); // Prevent dismissing by tapping outside
                builder.show();
            });
        }

        public void certError(final String alias) {
            s_cordova.getActivity().runOnUiThread(new Runnable() {
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
        request.proceed(mPrivateKey, mCertificates);
    }
}
