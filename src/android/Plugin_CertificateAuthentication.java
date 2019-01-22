package ch.migros.plugin;

import android.os.Handler;
import android.os.Looper;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.ICordovaClientCertRequest;

import android.content.Context;
import android.os.Build;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.util.Log;
import android.widget.Toast;
import android.preference.PreferenceManager;
import android.content.SharedPreferences;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

public class Plugin_CertificateAuthentication extends CordovaPlugin {

	private static final String TAG = Plugin_CertificateAuthentication.class.getName();

	private X509Certificate[] _certArr;
    private PrivateKey        _privKey;
    private String            _alias;
    

    @Override
    public boolean onReceivedClientCertRequest(CordovaWebView view, ICordovaClientCertRequest request) {
        Log.d(TAG, "Test Version 0.0.8");
        if (_certArr == null || _privKey == null) {
			Log.d(TAG, "onReceivedClientCertRequest().loadFromKeystore:  _certArr: " + _certArr + " / _privKey=" + _privKey);
            loadFromKeystore(request);
        } else {
			Log.d(TAG, "onReceivedClientCertRequest().requestProceed:  _certArr: " + _certArr + " / _privKey=" + _privKey);
            requestProceed(request);
        }
        return true;
    }

	
    public void requestProceed(ICordovaClientCertRequest request) {
		Log.d(TAG, "onReceivedClientCertRequest().requestProceed()");
        request.proceed(_privKey, _certArr);
    }
	
    /*
     * Read Alias form MDM stored file
     * Simply read one entry as plaintext
     */
    private String readAlias() {
        String alias = null;
        File f = null;
        BufferedReader b = null;
        try {
            f = new File("/enterprise/usr/mgb/reverseproxy_cert_alias.txt");
            b = new BufferedReader(new FileReader(f));
            String readLine = readLine = b.readLine();
            if (readLine != null) {
                alias = readLine;
                Log.d(TAG, "readAlias: "+alias);
            }
        } catch (Exception e) {
            Log.e(TAG, "readAlias: Exception caught. " + e.toString(), e);
        } finally {
            try {
                b.close();
            } catch (Exception silent) {
            }
        }
        return alias;
    }
	
    private void loadFromKeystore(ICordovaClientCertRequest request) {
     	
		//todo: read pattern from file based settings
		final KeyChainAliasCallback kcCallback = new KeyChainAliasCallbackImpl(cordova.getActivity(), request);
		//final String keystoreAlias="devicemgl172905225036425600010A14894EF2C5352EBCFF000000010A14";
        final String keystoreAlias=readAlias();
        
        
		Log.d(TAG, "loadFromKeystore().threadPool.submit()");

        if (keystoreAlias != null) {
			    //ExecutorService threadPool = cordova.getThreadPool();
				//threadPool.submit(new Runnable() {
                //@Override
                //public void run() {
				//	Log.d(TAG, "loadFromKeystore().run()");
                //    kcCallback.alias(keystoreAlias);
                //}
            //});
            
            
           new Thread(new Runnable() {
                @Override
                public void run() {
                    runOnUiThread(new Runnable() {
                        public void run() {
                            Log.d(TAG, "loadFromKeystore().run()");
                            kcCallback.alias(keystoreAlias);
                        }
                    });
            }
            }).start();


            
        } else {
			Log.d(TAG, "loadFromKeystore().choosePrivateKeyAlias with " + keystoreAlias);
            KeyChain.choosePrivateKeyAlias(cordova.getActivity(), kcCallback
			                              ,new String[]{"RSA"}, null
										  ,request.getHost(), request.getPort(), null);
        }
    }


	/**
	 * Convenience Methode für das Starten von Runnables
	 * auf dem UI Thread aus Background Threads
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

    static class KeyChainAliasCallbackImpl implements KeyChainAliasCallback {

        private final Context _ctx;
		private final SharedPreferences _sharedPrefs;
        private final ICordovaClientCertRequest _request;

        public KeyChainAliasCallbackImpl(Context context, ICordovaClientCertRequest request) {
            _ctx = context;
            _request = request;
            _sharedPrefs = PreferenceManager.getDefaultSharedPreferences(_ctx);
        }

        @Override
        public void alias(String keystoreAlias) {
			Log.d(TAG, "KeyChainAliasCallbackImpl.alias() keystoreAlias=" + keystoreAlias);
            try {
                if (keystoreAlias != null) {
                    Log.d(TAG, "getPrivateKey (if)");
                    PrivateKey pk = KeyChain.getPrivateKey(_ctx, keystoreAlias);
					Log.d(TAG, "PrivateKey="+pk.toString());
					
                    X509Certificate[] cert = KeyChain.getCertificateChain(_ctx, keystoreAlias);
					Log.d(TAG, "X509Certificate="+cert.toString());
					Log.d(TAG, "alias.proceed (if)");
                    _request.proceed(pk, cert);
                } else {
					Log.d(TAG, "alias.proceed (else)");
                    _request.proceed(null, null);
                }
            } catch (Exception ex) {
                String txt = "alias() Cannot load certificates. Exception="+ex.toString();
                Log.e(TAG, txt, ex);
               
            }
        }
    };
}
