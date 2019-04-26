package org.crypthing.security;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.security.PublicKey;

import org.crypthing.security.provider.NharuProvider;
import org.crypthing.util.NharuArrays;

/**
 * Nharu Public Key implementation
 * @author yorick.flannagan@gmail.com
 *
 */
public class NharuPublicKey implements PublicKey
{
	/*
	 * java.security.KeyPairGenerator algorithm constants.
	 */
	static final int NHIX_DSA_ALGORITHM = 1;
	static final int NHIX_RSA_ALGORITHM = 2;

	private static final long serialVersionUID = 6349591703890493892L;
	static { NharuProvider.isLoaded(); }
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObjectNoData() throws ObjectStreamException { throw new NotSerializableException(); }

	/**
	 * Creates a new java.security.PublicKey instance
	 * @param encoding: PublicKeyInfo DER encoding
	 * @return requested public key.
	 * @throws EncodingException on error.
	 */
	@SuppressWarnings("restriction")
	public static PublicKey newInstance(final byte[] encoding) throws EncodingException
	{
		PublicKey ret = null;
		NharuPublicKey me = new NharuPublicKey(encoding);
		final int type = nhixGetPublicKeyType(me.hHandle);
		switch (type)
		{
		case NHIX_DSA_ALGORITHM:
			me.releaseObject();
			try { ret = new sun.security.provider.DSAPublicKeyImpl(encoding); }
			catch (final java.security.InvalidKeyException e) { throw new EncodingException(e.getMessage(), e); }
			break;
		case NHIX_RSA_ALGORITHM:
			me.algorithm = "RSA";
			ret = me;
			break;
		default:
			me.releaseObject();
			throw new EncodingException("Unsupported key type " + type);
		}
		return ret;
	}

	private final byte[] encoding;
	protected long hHandle;
	private String algorithm;
	private int hash = 0;
	protected NharuPublicKey(final byte[] encoding) throws EncodingException
	{
		if ((this.encoding = encoding) == null) throw new EncodingException("Argument must not be null");
		hHandle = nhixParsePublicKey(encoding);
	}
	public void releaseObject()
	{
		if (hHandle != 0)
		{
			nhixReleasePublicKey(hHandle);
			hHandle = 0;
		}
	}
	protected void recallHandle()
	{
		if (hHandle == 0)
		{
			try { hHandle = nhixParsePublicKey(encoding); }
			catch (EncodingException e) { throw new RuntimeException(e); }
		}
	}
	@Override
	public String getAlgorithm()
	{
		if (algorithm == null)
		{
			recallHandle();
			switch (nhixGetPublicKeyType(hHandle))
			{
			case NHIX_DSA_ALGORITHM: algorithm = "DSA"; break;
			case NHIX_RSA_ALGORITHM: algorithm = "RSA"; break;
			default: throw new RuntimeException("Unsupported key type");
			}
		}
		return algorithm;
	}
	@Override public String getFormat() { return "SubjectPublicKeyInfo"; }
	@Override public byte[] getEncoded() { return encoding; }
	@Override
	public boolean equals(final Object other)
	{
		if (this == other) return true;
		if (!(other instanceof NharuPublicKey)) return false;
		return NharuArrays.equals(((PublicKey) other).getEncoded(), getEncoded());
	}
	@Override
	public int hashCode()
	{
		if (hash == 0) hash = NharuArrays.hashCode(getEncoded());
		return hash;
	}

	private static native long nhixParsePublicKey(byte[] encoding) throws EncodingException;
	private static native void nhixReleasePublicKey(long handle);
	private static native int nhixGetPublicKeyType(long handle);
}
