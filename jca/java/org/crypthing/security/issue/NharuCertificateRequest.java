package org.crypthing.security.issue;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.security.SignatureException;

import javax.security.auth.x500.X500Principal;

import org.crypthing.security.EncodingException;
import org.crypthing.security.NharuRSAPublicKey;
import org.crypthing.security.provider.NharuProvider;

/**
 * Implements basic operations on RFC 2986 documents PKCS #10: Certification
 * Request Syntax Specification
 * 
 */
public class NharuCertificateRequest
{
	static { NharuProvider.isLoaded(); }
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws NotSerializableException { throw new NotSerializableException(); }

	/**
	 * Parses specified PKCS#10 document.
	 * @param encoding: DER encoded PKCS#10 document.
	 * @return an instance of NharuCertificateRequest
	 * @throws EncodingException if an invalid encoding is found.
	 */
	public static NharuCertificateRequest parse(final byte[] encoding) throws EncodingException
	{
		return new NharuCertificateRequest(encoding, nhCertParseRequest(encoding));
	}

	private final byte[] encoding;
	private long hHandle;
	private X500Principal subject;

	private NharuCertificateRequest(final byte[] encoding, final long hHandle)
	{
		this.encoding = encoding;
		this.hHandle = hHandle;
	}

	/**
	 * Gets PKCS#10 subject as a "stringprep" (RFC 3454)
	 * @return a X.500 Name
	 */
	public X500Principal getSubject()
	{
		if (subject == null)
		{
			if (hHandle == 0) recallHandle();
			final byte[] value = nhCertGetSubject(hHandle);
			subject = new X500Principal(value);
		}
		return subject;
	}

	/**
	 * Gets PKCS#10 subjectPKInfo field.
	 * 
	 * @return an instance of RSAPublicKey.
	 */
	public NharuRSAPublicKey getPublicKey()
	{
		// TODO: NharuRSAPublicKey must support NharuCertificateRequest
		// parenthood
		return null;
	}

	/**
	 * Verifies PKCS#10 signature
	 * 
	 * @throws SignatureException
	 *                                  if cryptographic verification fails
	 */
	public void verify() throws SignatureException
	{

	}

	/**
	 * Releases this object. Must be called when object is no more needed
	 */
	public void releaseObject()
	{
		if (hHandle != 0)
		{
			nhCertReleaseRequestParser(hHandle);
			hHandle = 0;
		}
	}

	private void recallHandle()
	{
		if (hHandle == 0)
		{
			try { hHandle = nhCertParseRequest(encoding); }
			catch (final EncodingException e) { throw new RuntimeException(e); }
		}
	}

	private static native long nhCertParseRequest(byte[] encoding) throws EncodingException;
	private static native void nhCertReleaseRequestParser(long hHandle);
	private static native byte[] nhCertGetSubject(long hHandle);



	/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 * Basic tests
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 */
	private static final String CERTIFICATE_REQUEST = "-----BEGIN CERTIFICATE REQUEST-----"
			+ "MIICfzCCAWcCAQAwOjE4MDYGA1UEAxMvRnJhbmNpc3ZhbGRvIEdlbmV2YWxkbyBkYXMgVG9y"
			+ "cmVzIDE1NTQ5MjIxNjMzMDkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3kovY"
			+ "zXeZffGdU0+x28ZQItmr17BAowwF1cu7aX2kw9qS8amMBhRaLvYfS61wnqKE52C+g9rgCsA8"
			+ "5TLp8V25zLxMoheriRPoFogy1Y/io2LnKxsKEpR6OugtjGHOwo9C7FggqJ7p7IRmz9OJlLvB"
			+ "6/BuJ8np+H2dXVPB2hgFW37ku3hJrL5XyRFFIzL2K33ti93hgt/c5pPIVgIML4tVY5knh+Tn"
			+ "kCqqQu7Kzc3SdXmUN+r3Qe/wkMMKX1NnMOUochZI1zNJkt50yAXzMTYBVaZjUi4OEv0xviZw"
			+ "EzpofVeA9KaEPwAQtAktz8bcbXlgqVVbHWtMkkMwkEKAWWB9AgMBAAGgADANBgkqhkiG9w0B"
			+ "AQsFAAOCAQEAVAhcy2MXgkv/vQOURcuw67A5XX01wSsqF9Sg5mswyVz924JQKwIIXm3FwBRU"
			+ "6qx0zeN1969I6kLbCu+SU3iyoIQB7CrmXjgMSYUhjBrUv2z/FzbaH29BWUCWYuvWEqHXGiDO"
			+ "nlVhS24RpzMEleYEo9v5jni/hpBkjbfvQGPn34bolecm7D7NIiRFr9Gbgl24cl0PVLhyRung"
			+ "L1VL/5fQok3SRgTSUaG4As8mjmuroZNc1ibeoXaRi7QlPjDcCWd0p4Zrzh8PsLuA38kkyEuN"
			+ "LcFIkSjPFU9Wh+OW8XJxB6yiEN/um0sCjr9lnpoEXq7PfE1CaYGQZRMHZGUEwZvGsQ=="
			+ "-----END CERTIFICATE REQUEST-----";
	private static final String FRANCISVALDO = "CN=Francisvaldo Genevaldo das Torres 1554922163309";
	public static void main(String[] args)
	{
		System.out.println("Validating PKCS#10 parsing...");
		try
		{
			NharuCertificateRequest request = NharuCertificateRequest.parse(CERTIFICATE_REQUEST.getBytes());
			try
			{
				System.out.print("Validating certificate request subject... ");
				X500Principal subject = request.getSubject();
				if (!subject.getName().equalsIgnoreCase(FRANCISVALDO)) throw new RuntimeException("Could not validate certificate request subject");
				System.out.println("Done!");
			}
			finally { request.releaseObject(); }
		}
		catch (Exception e) { e.printStackTrace(); }
	}
}