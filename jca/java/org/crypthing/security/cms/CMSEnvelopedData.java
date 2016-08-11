package org.crypthing.security.cms;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.security.UnrecoverableKeyException;

import org.crypthing.security.DecryptInterface;
import org.crypthing.security.provider.NharuProvider;

/**
 * Parses a CMS EnvelopedData document. Only a single KeyTransRecipientInfo recipient is currently supported.
 * @author magut
 *
 */
public final class CMSEnvelopedData
{
	static { NharuProvider.isLoaded(); }
	private long hHandle;
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws NotSerializableException { throw new NotSerializableException(); }
	private void readObjectNoData() throws ObjectStreamException { throw new NotSerializableException(); }

	private static native long nhcmsParseEnvelopedData(byte[] encoding) throws CMSParsingException;
	private static native void nhcmsReleaseHandle(long handle);
	private static native byte[] nhcmsDecrypt(long handle, DecryptInterface decrypt) throws CMSException;
	private static native IssuerAndSerialNumber getRID(long handle) throws CMSParsingException;

	private byte[] eContent;
	/**
	 * Creates a new CMSEnvelopedData instance. Only key transport recipients is supported.
	 * @param encoding: document DER encoding
	 * @throws CMSParsingException
	 */
	public CMSEnvelopedData(final byte[] encoding) throws CMSParsingException
	{
		if (encoding == null) throw new NullPointerException("Encoding argument must not be null");
		hHandle = nhcmsParseEnvelopedData(encoding);
	}

	/**
	 * Get the type of this RecipientInfo
	 * @return the type. Only key transport envelope is supported.
	 */
	public RecipientInfoType getRecipType() { return RecipientInfoType.KeyTransRecipientInfo;	}

	/**
	 * Releases this object. Must be called when object is no more needed 
	 */
	public void releaseDocument()
	{
		if (hHandle != 0)
		{
			nhcmsReleaseHandle(hHandle);
			hHandle = 0;
		}
	}

	/**
	 * Get enveloped plain text.
	 * @param store: key store that should be used for RSA private decryption.
	 * @return plain text as is.
	 * @throws UnrecoverableKeyException 
	 * @throws CMSException 
	 */
	public byte[] decrypt(final NharuKeyStore store) throws UnrecoverableKeyException, CMSException
	{
		if (store == null) throw new NullPointerException("Argument must not be null");
		if (eContent == null)
		{
			if (hHandle == 0) throw new IllegalStateException("Object already released");
			IssuerAndSerialNumber issuer = getRID(hHandle);
			final DecryptInterface decrypt = store.getDecrypt(issuer);
			if (decrypt == null) throw new UnrecoverableKeyException("Key store does not have a private key capable to decrypt this document");
			eContent = nhcmsDecrypt(hHandle, decrypt);
		}
		return eContent;
	}

	public enum RecipientInfoType
	{
		KeyTransRecipientInfo,
		KeyAgreeRecipientInfo,
		KEKRecipientInfo,
		PasswordRecipientinfo,
		OtherRecipientInfo
	}
}
