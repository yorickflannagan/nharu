package org.crypthing.security.cms;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;

import org.crypthing.security.provider.NharuProvider;

public final class CMSEnvelopedData
{
	static { NharuProvider.isLoaded(); }
	private long hHandle;
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws NotSerializableException { throw new NotSerializableException(); }
	private void readObjectNoData() throws ObjectStreamException { throw new NotSerializableException(); }

	private static native long nhcmsParseEnvelopedData(byte[] encoding) throws CMSParsingException;
	private static native void nhcmsReleaseHandle(long handle);

	public CMSEnvelopedData(final byte[] encoding) throws CMSParsingException
	{
		if (encoding == null) throw new NullPointerException("Encoding argument must not be null");
		hHandle = nhcmsParseEnvelopedData(encoding);
	}

	public RecipientInfoType getRecipType()
	{
		return RecipientInfoType.KeyTransRecipientInfo;	// Only key transport envelope is supported
	}

	public void releaseDocument()
	{
		if (hHandle != 0)
		{
			nhcmsReleaseHandle(hHandle);
			hHandle = 0;
		}
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
