package org.crypthing.security.issue;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.security.SignatureException;

import org.crypthing.security.NharuRSAPublicKey;
import org.crypthing.security.provider.NharuProvider;

/**
 * Implements basic operations on RFC 2986 documents
 * PKCS #10: Certification Request Syntax Specification
 * 
 */
public class NharuCertificateRequest
{
	static { NharuProvider.isLoaded(); }
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws NotSerializableException { throw new NotSerializableException(); }
	
	/**
	 * Parses specified PKCS#10 document.
	 * 
	 * @param encoding: DER encoded PKCS#10 document.
	 * @return an instance of NharuCertificateRequest
	 * @throws EncodingException if an invalid encoding is found.
	 */
	public static NharuCertificateRequest parse(final byte[] encoding) throws EncodingException
	{
		return null;
	}

	/**
	 * Gets PKCS#10 subject as a "stringprep" (RFC 3454)
	 * @return a stringprep X.500 Name
	 */
	public String getSubject()
	{
		return null;
	}

	/**
	 * Gets PKCS#10 subjectPKInfo field.
	 * @return an instance of RSAPublicKey.
	 */
	public NharuRSAPublicKey getPublicKey()
	{
		// TODO: NharuRSAPublicKey must support NharuCertificateRequest parenthood
		return null;
	}

	/**
	 * Verifies PKCS#10 signature
	 * @throws SignatureException if cryptographic verification fails
	 */
	public void verify() throws SignatureException
	{
		
	}

	/**
	 * Releases this object. Must be called when object is no more needed 
	 */
	public void releaseObject()
	{

	}
}