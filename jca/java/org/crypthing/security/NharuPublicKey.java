package org.crypthing.security;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.security.PublicKey;

import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.util.NharuArrays;

/**
 * Nharu Public Key implementation
 * @author magut
 *
 */
public class NharuPublicKey implements PublicKey
{
	/*
	 * java.security.KeyPairGenerator algorithm constants.
	 */
	static final int NHIX_DSA_ALGORITHM = 1;
	static final int NHIX_RSA_ALGORITHM = 2;
	static final int NHIX_EC_ALGORITHM = 3;

	private static final long serialVersionUID = 6349591703890493892L;
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObjectNoData() throws ObjectStreamException { throw new NotSerializableException(); }

	/**
	 * Creates a new java.security.PublicKey instance from this certificate PublicKeyInfo
	 * @param parent
	 * @return
	 */
	public static PublicKey newInstance(final NharuX509Certificate parent)
	{
		PublicKey ret = null;
		final int type = nhixGetPublicKeyType(parent.getCertificateHandle());
		switch (type)
		{
		// TODO: Must support DSA
		case NHIX_DSA_ALGORITHM:
			try { ret = new sun.security.provider.DSAPublicKeyImpl(nhixGetPublicKeyInfo(parent.getCertificateHandle())); }
			catch(final java.security.InvalidKeyException e) { throw new RuntimeException(e.getMessage(), e); }
			break;
		case NHIX_RSA_ALGORITHM:
			ret = new NharuRSAPublicKey(parent, type);
			break;
		// TODO: Must support ECDSA
		case NHIX_EC_ALGORITHM:
			try { ret = new sun.security.ec.ECPublicKeyImpl(nhixGetPublicKeyInfo(parent.getCertificateHandle())); }
			catch(java.security.InvalidKeyException e) { throw new RuntimeException(e.getMessage(),e); }
			break;
		default: throw new RuntimeException("Unsupported key type " + type);
		}
		return ret;
	}

	protected final NharuX509Certificate parent;
	protected final int type;
	private int hash = 0;

	protected NharuPublicKey(final NharuX509Certificate parent, final int type)
	{
		this.parent = parent;
		this.type = type;
	}
	
	@Override
	public String getAlgorithm()
	{
		switch (type)
		{
		case NHIX_DSA_ALGORITHM: return "DSA";
		case NHIX_RSA_ALGORITHM: return "RSA";
		case NHIX_EC_ALGORITHM: return "EC";
		default: throw new RuntimeException("Unsupported key type " + type);
		}
	}

	@Override public String getFormat() { return "SubjectPublicKeyInfo"; }
	@Override public byte[] getEncoded() { return nhixGetPublicKeyInfo(parent.getCertificateHandle()); }

	@Override
	public boolean equals(final Object other)
	{
		if (this == other) return true;
		if (!(other instanceof NharuPublicKey)) return false;
		final byte[] otherEncoding = ((PublicKey) other).getEncoded();
		return NharuArrays.equals(otherEncoding, nhixGetPublicKeyInfo(parent.getCertificateHandle()));
	}

	@Override
	public int hashCode()
	{
		if (hash == 0) hash = NharuArrays.hashCode(nhixGetPublicKeyInfo(parent.getCertificateHandle()));
		return hash;
	}

	private static native byte[] nhixGetPublicKeyInfo(long handle);
	private static native int nhixGetPublicKeyType(long handle);
}
