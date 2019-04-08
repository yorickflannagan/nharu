package org.crypthing.security;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPrivateKey;

import org.crypthing.security.provider.NharuProvider;
import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.util.NharuCommon;

/**
 * Implements a RSA private key DER encoded as a plain text
 * @author magut
 *
 */
public final class NharuRSAPrivateKey implements RSAPrivateKey, SignerInterface, DecryptInterface
{
	static { NharuProvider.isLoaded(); }

	private long hHandle;
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws NotSerializableException { throw new NotSerializableException(); }
	private void readObjectNoData() throws ObjectStreamException { throw new NotSerializableException(); }
	private static final long serialVersionUID = -4864032840615951991L;
	private final byte[] encoding;
	private NharuX509Certificate[] chain;

	/**
	 * Creates a new NharuRSAPrivateKey instance
	 * @param encoding: DER encoding of RSA private key attributes according to RFC 3447
	 * @throws InvalidKeyException on error
	 */
	public NharuRSAPrivateKey(final byte[] encoding) throws InvalidKeyException { this(encoding, null); }

	/**
	 * Creates a new NharuRSAPrivateKey instance
	 * @param encoding: DER encoding of RSA private key attributes according to RFC 3447
	 * @param chain: certificate chain associated to this private key.
	 * @throws InvalidKeyException on error
	 */
	public NharuRSAPrivateKey(final byte[] encoding, final NharuX509Certificate[] chain) throws InvalidKeyException
	{
		this.encoding = encoding;
		hHandle = nharuNewRSAPrivateKey(encoding);
		this.chain = chain;
	}

	/**
	 * Releases this object. Must be called when object is no more needed 
	 */
	public void releaseObject()
	{
		if (hHandle != 0)
		{
			nharuReleaseRSAPrivateKey(hHandle);
			hHandle = 0;
		}
	}

	/**
	 * Signs specified buffer with this private key
	 * @param data: the buffer
	 * @param algorithm: signature algorithm. Only SHA1withRSA, SHA256withRSA, SHA384withRSA, SHA512withRSA and MD5withRSA are supported.
	 * @return the signature itself.
	 * @throws GeneralSecurityException (an instance of java.security.KeyException) if data could not be signed.
	 */
	@Override
	public byte[] sign(final byte[] data, final String algorithm) throws GeneralSecurityException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		return nharuRSASign(hHandle, data, NharuCommon.getAlgorithmConstant(algorithm));
	}

	/**
	 * Gets the length of the signature byte array.
	 * @param algorithm: ignored.
	 * @return the signature length.
	 */
	@Override
	public int signatureLength(final String algorithm)
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		return nharuRSASignatureLength(hHandle);
	}

	@Override
	public int plainTextLength(final String padding) { return signatureLength(padding); }

	/**
	 * Private decrypt contents.
	 * @param data: the buffer
	 * @param padding: RSA private decryption algorithm. Only PKCS1Padding, OAEPPadding and NoPadding are supported.
	 * @return the plaintext
	 * @throws GeneralSecurityException on failure
	 */
	@Override
	public byte[] decrypt(final byte[] data, final String padding) throws GeneralSecurityException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		return nharuRSADecrypt(hHandle, data, NharuCommon.getAlgorithmConstant(padding));
	}

	/**
	 * Sets certificate chain associated to this private key.
	 * @param chain: the chain itself. It is assumed that the chain is valid.
	 */
	public void setChain(final NharuX509Certificate[] chain) { this.chain = chain; }

	/**
	 * Gets the certificate chain associated to this private key.
	 * @return the chain or null.
	 */
	public NharuX509Certificate[] getChain() { return chain; }

	@Override
	public BigInteger getModulus()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		return new BigInteger(nharuGetRSAModulus(hHandle));
	}
	@Override
	public BigInteger getPrivateExponent()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		return new BigInteger(nharuGetRSAPrivateExponent(hHandle));
	}
	@Override public byte[] getEncoded() { return encoding; }
	@Override public String getAlgorithm() { return "RSA"; }
	@Override public String getFormat() { return "PKCS#8"; }


	private static native long nharuNewRSAPrivateKey(byte[] encoding) throws InvalidKeyException;
	private static native void nharuReleaseRSAPrivateKey(long handle);
	private static native byte[] nharuGetRSAModulus(long handle);
	private static native byte[] nharuGetRSAPrivateExponent(long handle);
	private static native byte[] nharuRSASign(long handle, byte[] data, int mechanism) throws InvalidKeyException;
	private static native int nharuRSASignatureLength(long handle);
	private static native byte[] nharuRSADecrypt(long handle, byte[] data, int mechanism) throws InvalidKeyException;
}
