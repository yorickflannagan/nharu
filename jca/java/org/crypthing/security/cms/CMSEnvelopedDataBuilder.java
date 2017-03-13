package org.crypthing.security.cms;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.security.NoSuchAlgorithmException;

import org.crypthing.security.provider.NharuProvider;
import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.util.NharuCommon;

/**
 * CMS EnvelopedData builder
 * @author magut
 *
 */
public final class CMSEnvelopedDataBuilder
{
	static { NharuProvider.isLoaded(); }
	private long hHandle;
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws NotSerializableException { throw new NotSerializableException(); }
	private void readObjectNoData() throws ObjectStreamException { throw new NotSerializableException(); }

	private static native long nhcmsNewEnvelopedDataBuilder(byte[] content) throws CMSParsingException;
	private static native void nhcmsReleaseEnvelopedDataBuilder(long handle);
	private static native void nhcmsEncrypt(long handle, int keyGenAlgorithm, int keySize, int cipherAlgorithm) throws CMSEncryptException;
	private static native void nhcmsAddKeyTransRecip(long cmsHandle, long certHandle, int padding) throws CMSEncryptException;
	private static native byte[] nhcmsEncode(long handle) throws CMSParsingException;

	/**
	 * Creates a new builder encrypt to specified plain text.
	 * @param eContent: the content to be encrypted
	 * @throws CMSParsingException
	 */
	public CMSEnvelopedDataBuilder(final byte[] eContent) throws CMSParsingException
	{
		if (eContent == null) throw new NullPointerException("Encrypted Content argument must not be null");
		hHandle = nhcmsNewEnvelopedDataBuilder(eContent);
	}

	/**
	 * Encrypts enveloped contents. This method must be called prior to addKeyTransRecip();
	 * @param keyGenAlgortihm: symmetric key generation algorithm
	 * @param keySize: key size. Must be consistent to keyGenAlgortihm. Only DESede, RC2 and AES are supported.
	 * @param cipherAlgorithm: encryption algorithm. Must be consistent to keyGenAlgortihm. Only DESede-CBC, RC2-CBC and AES-CBC are supported.
	 * @throws CMSEncryptException
	 * @throws NoSuchAlgorithmException
	 */
	public void encrypt(final String keyGenAlgortihm, final int keySize, final String cipherAlgorithm) throws CMSEncryptException, NoSuchAlgorithmException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		nhcmsEncrypt(hHandle, NharuCommon.getAlgorithmConstant(keyGenAlgortihm), keySize, NharuCommon.getAlgorithmConstant(cipherAlgorithm));
	}

	/**
	 * Adds a KeyTransRecipientInfo for specified certificate. Must be called after encrypt().
	 * @param recip: Recipient certificate. Must be generated for an RSA key.
	 * @param padding: RSA padding algorithm. Only PKCS1Padding, OAEPPadding and NoPadding are supported.
	 * @throws CMSEncryptException
	 * @throws NoSuchAlgorithmException
	 */
	public void addKeyTransRecip(final NharuX509Certificate recip, final String padding) throws CMSEncryptException, NoSuchAlgorithmException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (recip == null) throw new NullPointerException("Recip argument must not be null");
		nhcmsAddKeyTransRecip(hHandle, recip.getCertificateHandle(), NharuCommon.getAlgorithmConstant(padding));
	}

	/**
	 * Encodes CMS document.
	 * @return DER encoded CMS EnvelopedData document.
	 * @throws CMSParsingException
	 */
	public byte[] encode() throws CMSParsingException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		return nhcmsEncode(hHandle);
	}

	/**
	 * Releases native handler. Must be called once when object is no longer needed.
	 */
	public void releaseBuilder()
	{
		if (hHandle != 0)
		{
			nhcmsReleaseEnvelopedDataBuilder(hHandle);
			hHandle = 0;
		}
	}
}
