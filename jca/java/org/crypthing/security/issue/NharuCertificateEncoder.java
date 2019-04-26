package org.crypthing.security.issue;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;

import org.crypthing.security.EncodingException;
import org.crypthing.security.SignerInterface;
import org.crypthing.security.provider.NharuProvider;

public class NharuCertificateEncoder
{

	static { NharuProvider.isLoaded(); }
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws NotSerializableException { throw new NotSerializableException(); }

	public NharuCertificateEncoder(final String profile) throws ParameterException
	{
		final CertificateParams in = new CertificateParams(profile);
	}

	/**
	 * Signs this certificate.
	 * 
	 * @param algorithm: signature algorithm. Only SHA1withRSA, SHA256withRSA,
	 *                   SHA384withRSA, SHA512withRSA and MD5withRSA are supported.
	 *                   Must conform signature field of certificate profile.
	 * @param signer:    signing callback. Must also implements
	 *                   java.security.interfaces.RSAPrivateKey.
	 * @throws GeneralSecurityException on failure.
	 */
	public void sign(final String algorithm, final SignerInterface signer) throws GeneralSecurityException
	{

	}

	/**
	 * Encodes this certificate, if signed.
	 * 
	 * @return a DER encoded X.509 Certificate.
	 * @throws EncodingException on failure.
	 */
	public byte[] encode() throws EncodingException
	{
		return null;
	}

	/**
	 * Releases this object. Must be called when object is no more needed
	 */
	public void releaseObject()
	{

	}
}