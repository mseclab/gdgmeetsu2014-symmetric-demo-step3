package com.mseclab.gdgmeetsu2014.symmetricdemostep3;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.mseclab.gdgmeetsu2014.symmetricdemostep3.R;

import android.os.Bundle;
import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends Activity {

	private TextView outView;
	private EditText mInData;
	private EditText mOutData;

	private final static String TAG = "GDG";
	private final static String TRANSFORMATION = "AES/CBC/PKCS5Padding";
	private final static int KEY_LEN = 128;
	private final static String PREF_NAME = "GDGFile";
	private final static String PREF_KEY = "key_pref";

	// NEVED DO THIS....
	private static final byte[] IV = "1234567890abcdef".getBytes();

	private static SecretKey key = null;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		outView = (TextView) findViewById(R.id.out_view);
		mInData = (EditText) findViewById(R.id.inDataText);
		mOutData = (EditText) findViewById(R.id.outDataText);

		// Set Action Bar Title
		getActionBar().setTitle(R.string.action_bar_title);
		getActionBar().setSubtitle(R.string.action_bar_subtitle);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle presses on the action bar items
		switch (item.getItemId()) {
		case R.id.action_discard:
			outView.setText("");
			key = null;
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	public boolean isKeyReady() {
		if (key == null) {
			// Load Key
			SharedPreferences settings = getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
			String prefKey = settings.getString(PREF_KEY, null);

			if (prefKey == null) {
				debug("Generating new key");
				debug("Applying PRNGFixes...");
				PRNGFixes.apply();
				// Create new key
				SecureRandom secureRandom = new SecureRandom();
				KeyGenerator keyGenerator;
				try {
					keyGenerator = KeyGenerator.getInstance("AES");
				} catch (NoSuchAlgorithmException e) {
					debug("Algorithm not available");
					return false;
				}

				keyGenerator.init(KEY_LEN, secureRandom);
				key = keyGenerator.generateKey();
				// Store the key
				SharedPreferences.Editor editor = settings.edit();
				editor.putString(PREF_KEY, Base64.encodeToString(key.getEncoded(), Base64.DEFAULT));
				editor.commit();
			} else {
				debug("Read key from SharedPreferences");
				key = new SecretKeySpec(Base64.decode(prefKey, Base64.DEFAULT), TRANSFORMATION);
			}
		}
		debug("Key= " + Base64.encodeToString(key.getEncoded(), Base64.DEFAULT));
		return true;
	}

	public void onEncryptClick(View view) {
		byte[] input = mInData.getText().toString().getBytes();
		byte[] output = cipherData(Cipher.ENCRYPT_MODE, input);

		if (output != null) {
			String outputBase64 = Base64.encodeToString(output, Base64.DEFAULT);
			mOutData.setText(outputBase64);
		}

	}

	public void onDecryptClick(View view) {
		byte[] input = Base64.decode(mOutData.getText().toString().getBytes(), Base64.DEFAULT);
		byte[] output = cipherData(Cipher.DECRYPT_MODE, input);

		if (output != null) {
			mInData.setText(new String(output));
		}

	}

	private byte[] cipherData(int opMode, byte[] input) {
		if (!isKeyReady()) {
			debug("Key not ready...");
			return null;
		}

		// Get Cipher Instance
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(TRANSFORMATION);
		} catch (NoSuchAlgorithmException e) {
			debug("Algorithm not available");
			return null;
		} catch (NoSuchPaddingException e) {
			debug("Padding not available");
			return null;
		}

		// Init cipher
		try {
			cipher.init(opMode, key, new IvParameterSpec(IV));
		} catch (InvalidKeyException e) {
			debug("Key not valid: " + e.getMessage());
			return null;
		} catch (InvalidAlgorithmParameterException e) {
			debug("Cipher Algorithm parameters not valid: " + e.getMessage());
			return null;
		}

		// Encrypt data

		byte[] encryptedText;
		try {
			encryptedText = cipher.doFinal(input);
		} catch (IllegalBlockSizeException e) {
			debug("Illegal block size: " + e.getMessage());
			return null;
		} catch (BadPaddingException e) {
			debug("Bad paggind exception: " + e.getMessage());
			return null;
		}
		return encryptedText;
	}

	public void onShowProvidersClick(View view) {
		Provider[] providers = Security.getProviders();
		for (Provider provider : providers) {
			debug("Provider: " + provider.getName());
			debug("Version : " + Double.toString(provider.getVersion()));
			debug("Info    : " + provider.getInfo());
			debug("N. Services : " + Integer.toString(provider.getServices().size()));
			debug("");
		}
	}

	public void onShowSCServicesClick(View view) {
		Provider spongyCastle = Security.getProvider("SC");
		if (spongyCastle == null) {
			debug("Spongy Castle Provider not available!");
			return;
		}

		debug("Spongy Castle Services:");
		for (Provider.Service service : spongyCastle.getServices())
			debug("- " + service.getAlgorithm());

	}

	private void debug(String message) {
		Log.v(TAG, message);
		outView.append(message + "\n");
	}

}
