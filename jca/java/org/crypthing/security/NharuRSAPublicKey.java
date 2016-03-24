package org.crypthing.security;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

import org.crypthing.security.x509.NharuX509Certificate;


public final class NharuRSAPublicKey extends NharuPublicKey implements RSAPublicKey
{
	private static final long serialVersionUID = 6023121324073746434L;
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObjectNoData() throws ObjectStreamException { throw new NotSerializableException(); }

	private BigInteger modulus = null;
	private BigInteger exponent = null;

	NharuRSAPublicKey(NharuX509Certificate parent, final int type) { super(parent, type); }

	@Override
	public BigInteger getModulus()
	{
		if (modulus == null ) modulus = new BigInteger(nhixGetRSAKeyModulus(parent.getCertificateHandle()));
		return modulus;
	}

	@Override
	public BigInteger getPublicExponent()
	{
		if (exponent == null) exponent = new BigInteger(nhixGetRSAKeyPublicExponent(parent.getCertificateHandle()));
		return exponent;
	}

	public long getKeyHandle()
	{
		return nhixGetPublicKeyHandle(parent.getCertificateHandle());
	}

	private static native byte[] nhixGetRSAKeyModulus(long handle);
	private static native byte[] nhixGetRSAKeyPublicExponent(long handle);
	protected static native long nhixGetPublicKeyHandle(long handle);
}
