package org.crypthing.security;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;

import org.crypthing.security.provider.NharuProvider;
import org.crypthing.util.NharuCommon;

public class NharuRSAPrivateKey implements RSAPrivateKey
{
	static { NharuProvider.isLoaded(); }

	private long hHandle;
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws NotSerializableException { throw new NotSerializableException(); }
	private void readObjectNoData() throws ObjectStreamException { throw new NotSerializableException(); }
	private static final long serialVersionUID = -4864032840615951991L;
	private final byte[] encoding;

	public NharuRSAPrivateKey(final byte[] encoding) throws InvalidKeyException
	{
		this.encoding = encoding;
		hHandle = nharuNewRSAPrivateKey(encoding);
	}

	public void releaseObject()
	{
		if (hHandle != 0)
		{
			nharuReleaseRSAPrivateKey(hHandle);
			hHandle = 0;
		}
	}
	
	@Override
	public BigInteger getModulus()
	{
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public BigInteger getPrivateExponent()
	{
		// TODO Auto-generated method stub
		return null;
	}
	@Override public byte[] getEncoded() { return encoding; }
	@Override public String getAlgorithm() { return "RSA"; }
	@Override public String getFormat() { return "PKCS#8"; }

	public byte[] sign(final byte[] data, final String algorithm) throws GeneralSecurityException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		return nharuRSASign(hHandle, data, NharuCommon.getAlgorithmConstant(algorithm));
	}

	private static native long nharuNewRSAPrivateKey(byte[] encoding) throws InvalidKeyException;
	private static native void nharuReleaseRSAPrivateKey(long handle);

	private static native byte[] nharuRSASign(long handle, byte[] data, int mechanism) throws InvalidKeyException;
	private static native int nharuRSASignatureLength(long handle);
}
