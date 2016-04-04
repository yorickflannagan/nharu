package org.crypthing.security.cms;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.crypthing.security.DecryptInterface;
import org.crypthing.security.NharuRSAPrivateKey;
import org.crypthing.security.SignerInterface;
import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.security.x509.NharuX509Factory;

/**
 * Implements a private key store. This store mantains a signer PrivateKey and any mumber of private decryption keys...
 * @author magut
 *
 */
public class NharuKeyStore implements SignerInterface
{
	private static final String KEY_STORE_ENTRY = "javax.net.ssl.keyStore";
	private static final String KEY_STORE_PWD_ENTRY = "javax.net.ssl.keyStorePassword";
	private static final String KEY_STORE_PROV_ENTRY = "javax.net.ssl.keyStoreProvider";
	private static final String KEY_STORE_TYPE_ENTRY = "javax.net.ssl.keyStoreType";
	private static final String KEY_ALIAS_ENTRY = "org.crypthing.security.cms.NharuKeyStore.key";

	/**
	 * Creates a new NharuKeyStore instance using environment (javax.net.ssl.* entries) definitions.
	 * @return the key store instance.
	 * @throws KeyStoreException
	 * @throws UnrecoverableKeyException
	 */
	public static NharuKeyStore getInstance() throws KeyStoreException, UnrecoverableKeyException
	{
		String entry = System.getProperty(KEY_STORE_PROV_ENTRY);
		KeyStore store;
		try
		{
			if (entry != null) store = KeyStore.getInstance(System.getProperty(KEY_STORE_TYPE_ENTRY, "jks"), entry);
			else store = KeyStore.getInstance(System.getProperty(KEY_STORE_TYPE_ENTRY, "jks"));
			entry = System.getProperty(KEY_STORE_ENTRY);
			if (entry == null) throw new KeyStoreException("Invalid system property entry: " + KEY_STORE_ENTRY);
			final FileInputStream stream = new FileInputStream(entry);
			try
			{
				entry = System.getProperty(KEY_STORE_PWD_ENTRY);
				final char[] pwd = entry != null ? entry.toCharArray() : null;
				store.load(stream, pwd);
				return getInstance(store, pwd);
			}
			finally { stream.close(); }
		}
		catch (final NoSuchAlgorithmException | NoSuchProviderException | CertificateException | IOException e) { throw new KeyStoreException(e); } 
	}

	/**
	 * Creates a new NharuKeyStore instance from this java.security.KeyStore.
	 * @param from: the Java key store
	 * @param pwd: key store (and private key entries) password.
	 * @return the new key store.
	 * @throws KeyStoreException
	 * @throws UnrecoverableKeyException
	 * @throws CertificateEncodingException
	 * @throws CertificateException
	 */
	public static NharuKeyStore getInstance(final KeyStore from, final char[] pwd) throws KeyStoreException, UnrecoverableKeyException, CertificateEncodingException, CertificateException
	{
		if (from == null) throw new NullPointerException("Argument must not be null");
		String entry = System.getProperty(KEY_ALIAS_ENTRY);
		String alias = null;
		if (entry != null) alias = entry;
		else
		{
			final Enumeration<String> en = from.aliases();
			while (alias == null && en.hasMoreElements())
			{
				entry = en.nextElement();
				if (from.isKeyEntry(entry)) alias = entry;
			}
		}
		if (alias == null) throw new UnrecoverableKeyException();
		return new NharuKeyStore(from, pwd, alias);
	}


	private NharuRSAPrivateKey getKey(final KeyStore from, final char[] pwd, final String alias) throws KeyStoreException, UnrecoverableKeyException, CertificateEncodingException, CertificateException
	{
		try
		{
			final Key key = from.getKey(alias, pwd);
			if (key == null) throw new UnrecoverableKeyException("Java key store does not have a private key");
			final byte[] encoding = key.getEncoded();
			if (encoding == null || !"RSA".equalsIgnoreCase(key.getAlgorithm())) throw new UnrecoverableKeyException("Unsupported private key");
			final Certificate[] certs = from.getCertificateChain(alias);
			final NharuX509Certificate[] chain = new NharuX509Certificate[certs.length];
			for (int i = 0; i < certs.length; i++) chain[i] = NharuX509Factory.generateCertificate(((X509Certificate) certs[i]).getEncoded());
			return new NharuRSAPrivateKey(encoding, chain);
		}
		catch (final NoSuchAlgorithmException | InvalidKeyException e) { throw new KeyStoreException(e); }
	}
	private final NharuRSAPrivateKey signer;
	private final Map<IssuerAndSerialNumber, NharuRSAPrivateKey> recips;

	/**
	 * Creates a new RSA private keys store.
	 * @param from: Java key store from where all private keys should be retrieved 
	 * @param pwd: key store password
	 * @param signerAlias: alias of signing key. All other keys should be for decryption.
	 * @throws KeyStoreException
	 * @throws UnrecoverableKeyException
	 * @throws CertificateEncodingException
	 * @throws CertificateException
	 */
	public NharuKeyStore(final KeyStore from, final char[] pwd, final String signerAlias) throws KeyStoreException, UnrecoverableKeyException, CertificateEncodingException, CertificateException
	{
		if (from == null || signerAlias == null) throw new NullPointerException("Arguments must not be null");
		signer = getKey(from, pwd, signerAlias);
		recips = new HashMap<>();
		final Enumeration<String> en = from.aliases();
		while (en.hasMoreElements())
		{
			final String entry = en.nextElement();
			if (from.isKeyEntry(entry))
			{
				final NharuRSAPrivateKey key = getKey(from, pwd, entry);
				final NharuX509Certificate[] chain = key.getChain();
				if (chain != null && chain.length > 0) recips.put(new IssuerAndSerialNumber(chain[0].getIssuer(), chain[0].getSerial()), key);
			}
		}
	}

	/**
	 * Releases this object. Must be called when object is no more needed 
	 */
	public void releaseObject()
	{
		signer.releaseObject();
		final Iterator<IssuerAndSerialNumber> it = recips.keySet().iterator();
		while (it.hasNext()) recips.get(it.next()).releaseObject();
	}

	/**
	 * Gets the certificate chain associated to signer PrivateKey.
	 * @return the chain or null, if it is not present.
	 */
	public NharuX509Certificate[] getSignerChain() { return signer.getChain(); }

	/**
	 * Gets decryption private key associated to specified issuer and serial number.
	 * @param issuer: the issuer to search.
	 * @return decrypt implementation or null if issuer and serial number was not found.
	 */
	public DecryptInterface getDecrypt(final IssuerAndSerialNumber issuer) { return recips.get(issuer); }

	@Override public byte[] sign(final byte[] data, final String algorithm) throws GeneralSecurityException { return signer.sign(data, algorithm); }
	@Override public int signatureLength(String algorithm) { return signer.signatureLength(algorithm); }
}
