package org.crypthing.security.cms;

import static org.crypthing.security.LogDevice.LOG_LEVEL;
import static org.crypthing.security.LogDevice.LOG_LEVEL_INFO;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.util.Enumeration;

import org.crypthing.util.NharuCommon;

public class BlindSigner implements SignerInterface
{
	private static final String KEY_STORE_ENTRY = "javax.net.ssl.keyStore";
	private static final String KEY_STORE_PWD_ENTRY = "javax.net.ssl.keyStorePassword";
	private static final String KEY_STORE_PROV_ENTRY = "javax.net.ssl.keyStoreProvider";
	private static final String KEY_STORE_TYPE_ENTRY = "javax.net.ssl.keyStoreType";
	private static final String KEY_ALIAS_ENTRY = "org.crypthing.security.cms.BlindSigner.key";
	private static KeyStoreException ex = null;
	private static KeyStore keyStore = null;
	private static String alias = null;
	private static Key getKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException
	{
		if (keyStore == null || alias == null) throw new UnrecoverableKeyException("Could not access Java key store");
		final String pwd = System.getProperty(KEY_STORE_PWD_ENTRY);
		final Key signKey = keyStore.getKey(alias, pwd != null ? pwd.toCharArray() : null);
		if (signKey == null) throw new UnrecoverableKeyException("Java key store does not have a private key");
		return signKey;
	}
	static
	{
		String entry = System.getProperty(KEY_STORE_PROV_ENTRY);
		try
		{
			if (entry != null) keyStore = KeyStore.getInstance(System.getProperty(KEY_STORE_TYPE_ENTRY, "jks"), entry);
			else keyStore = KeyStore.getInstance(System.getProperty(KEY_STORE_TYPE_ENTRY, "jks"));
			final FileInputStream stream = new FileInputStream(System.getProperty(KEY_STORE_ENTRY));
			try
			{
				entry = System.getProperty(KEY_STORE_PWD_ENTRY);
				keyStore.load(stream, entry != null ? entry.toCharArray() : null);
				entry = System.getProperty(KEY_ALIAS_ENTRY);
				if (entry != null) alias = entry;
				else
				{
					final Enumeration<String> en = keyStore.aliases();
					while (alias == null && en.hasMoreElements())
					{
						entry = en.nextElement();
						if (keyStore.isKeyEntry(entry)) alias = entry;
					}
					if (alias == null) throw new UnrecoverableKeyException("Java key store does not have a private key");
				}
				getKey();
			}
			finally { stream.close(); }
		}
		catch (final GeneralSecurityException | IOException e) { ex = new KeyStoreException(e); } 
	}

	private long hHandle;
	public BlindSigner() throws GeneralSecurityException
	{
		if (ex != null) throw ex;
		final Key key = getKey();
		final byte[] encoding = key.getEncoded();
		if (encoding != null && "RSA".equalsIgnoreCase(key.getAlgorithm())) hHandle = nhcmsNewRSAPrivateKey(encoding);
		else hHandle = 0;
	}

	@Override
	public byte[] sign(byte[] data, String algorithm) throws GeneralSecurityException
	{
		byte[] ret = null;
		if (hHandle != 0)
		{
			final int mechanism = NharuCommon.getAlgorithmConstant(algorithm);
			ret = nhcmsRSASign(hHandle, data, mechanism);
		}
		else
		{
			final Key key = getKey();
			final Signature signer = Signature.getInstance(algorithm);
			signer.initSign((PrivateKey) key);
			signer.update(data);
			ret = signer.sign();
		}
		return ret;
	}

	@Override
	public int signatureLength(String algorithm)
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		return nhcmsRSASignatureLength(hHandle);
	}

	public void releaseObject()
	{
		if (hHandle != 0)
		{
			nhcmsReleaseRSAPrivateKey(hHandle);
			hHandle = 0;
		}
	}
	
	KeyStore getKeyStore()
	{
		KeyStore ret = null;
		if (LOG_LEVEL < LOG_LEVEL_INFO) ret = keyStore;
		return ret;
	}

	private static native long nhcmsNewRSAPrivateKey(byte[] encoding) throws InvalidKeyException;
	private static native void nhcmsReleaseRSAPrivateKey(long handle);
	private static native byte[] nhcmsRSASign(long handle, byte[] data, int mechanism) throws InvalidKeyException;
	private static native int nhcmsRSASignatureLength(long handle);
}
