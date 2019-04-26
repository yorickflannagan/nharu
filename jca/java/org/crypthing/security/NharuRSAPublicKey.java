package org.crypthing.security;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

import org.crypthing.security.provider.NharuDigest;
import org.crypthing.security.provider.NharuProvider;


/**
 * RSA PublicKey implementation
 * @author magut
 *
 */
public final class NharuRSAPublicKey extends NharuPublicKey implements RSAPublicKey
{
	private static final long serialVersionUID = 6023121324073746434L;
	static { NharuProvider.isLoaded(); }
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObjectNoData() throws ObjectStreamException { throw new NotSerializableException(); }

	private BigInteger modulus = null;
	private BigInteger exponent = null;
	private byte[] keyId = null;
	public NharuRSAPublicKey(final byte[] encoding) throws EncodingException { super(encoding); }
	@Override
	public BigInteger getModulus()
	{
		if (modulus == null ) modulus = new BigInteger(nhixGetRSAKeyModulus(hHandle));
		return modulus;
	}
	@Override
	public BigInteger getPublicExponent()
	{
		if (exponent == null) exponent = new BigInteger(nhixGetRSAKeyPublicExponent(hHandle));
		return exponent;
	}
	public long getInternalNode()
	{
		recallHandle();
		return nhixGetPublicKeyInfoNode(hHandle);
	}
	/**
	 * Calculates the SHA-1 hash of this key according to RFC 5280 section 4.2.1.2
	 * @return required hash value
	 * @since 1.3.0
	 */
	public byte[] getKeyIdentifier()
	{
		recallHandle();
		if (keyId == null) keyId = new NharuDigest.SHA().digestBuffer(getKeyEncoding(hHandle));
		return keyId;
	}

	private static native byte[] nhixGetRSAKeyModulus(long handle);
	private static native byte[] nhixGetRSAKeyPublicExponent(long handle);
	private static native long nhixGetPublicKeyInfoNode(long handle);
	private static native byte[] getKeyEncoding(long handle);
}
