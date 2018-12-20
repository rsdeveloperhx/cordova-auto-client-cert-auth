package ch.migros.plugin;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.ICordovaClientCertRequest;

import android.content.Context;
import android.os.Build;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.util.Log;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;


public class Plugin_CertificateAuthentication extends CordovaPlugin {

	private static final String TAG = Plugin_CertificateAuthentication.class.getName();

	private X509Certificate[] _certArr;
    private PrivateKey        _privKey;
    private String            _alias;
    

    @Override
    public boolean onReceivedClientCertRequest(CordovaWebView view, ICordovaClientCertRequest request) {
        if (_certArr == null || _privKey == null) {
            loadFromKeystore(request);
        } else {
            requestProceed(request);
        }
        return true;
    }

	
    public void requestProceed(ICordovaClientCertRequest request) {
        request.proceed(_privKey, _certArr);
    }
	
    private void loadFromKeystore(ICordovaClientCertRequest request) {
     	
		//todo: read pattern from file based settings
		
		final String keystoreAlias="devicemgl172155225084355600010359E7981339285E5D1F000000010359";

        if (keystoreAlias != null) {
			    ExecutorService threadPool = cordova.getThreadPool();
				threadPool.submit(new Runnable() {
                @Override
                public void run() {
                    callback.alias(keystoreAlias);
                }
            });
        } else {
            KeyChain.choosePrivateKeyAlias(cordova.getActivity(), callback
			                              ,new String[]{"RSA"}, null
										  ,request.getHost(), request.getPort(), null);
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
            try {
                if (alias != null) {
                    PrivateKey pk = KeyChain.getPrivateKey(_ctx, keystoreAlias);
                    X509Certificate[] cert = KeyChain.getCertificateChain(_ctx, keystoreAlias);
                    _request.proceed(pk, cert);
                } else {
                    _request.proceed(null, null);
                }
            } catch (Exception ex) {
                String txt = "Cannot load certificates. Exception="+ex.toString();
                Toast.makeText(_ctx, txt, Toast.LENGTH_SHORT).show();
                Log.e(TAG, txt, ex);
            }
        }
    };
}
