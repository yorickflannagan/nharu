package org.crypthing.security.issue;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.security.SignatureException;

import javax.security.auth.x500.X500Principal;

import org.crypthing.security.EncodingException;
import org.crypthing.security.NharuRSAPublicKey;
import org.crypthing.security.provider.NharuProvider;
import org.crypthing.util.NharuArrays;

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
	private NharuRSAPublicKey pubkey;

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
			recallHandle();
			final byte[] value = nhCertGetSubject(hHandle);
			subject = new X500Principal(value);
		}
		return subject;
	}

	/**
	 * Gets PKCS#10 subjectPKInfo field.
	 * @return an instance of RSAPublicKey.
	 */
	public NharuRSAPublicKey getPublicKey()
	{
		if (pubkey == null)
		{
			recallHandle();
			try { pubkey = new NharuRSAPublicKey(nhCertGetPubkey(hHandle)); }
			catch (EncodingException e) { throw new RuntimeException(e); }
		}
		return pubkey;
	}

	/**
	 * Verifies PKCS#10 signature
	 * @throws SignatureException if cryptographic verification fails
	 */
	public void verify() throws SignatureException
	{
		recallHandle();
		nhCertVerify(hHandle);
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
	private static native byte[] nhCertGetPubkey(long handle);
	private static native void nhCertVerify(long handle) throws SignatureException;



	/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 * Basic tests
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 */
	private static final String CERTIFICATE_REQUEST =
		"-----BEGIN CERTIFICATE REQUEST-----"
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
	private static final byte[] PUBKEY =
	{
		(byte) 0x30,  (byte) 0x82,  (byte) 0x01,  (byte) 0x22,  (byte) 0x30,  (byte) 0x0D,  (byte) 0x06,  (byte) 0x09,  (byte) 0x2A,
		(byte) 0x86,  (byte) 0x48,  (byte) 0x86,  (byte) 0xF7,  (byte) 0x0D,  (byte) 0x01,  (byte) 0x01,  (byte) 0x01,  (byte) 0x05,  (byte) 0x00,  (byte) 0x03,  (byte) 0x82,  (byte) 0x01,  (byte) 0x0F,  (byte) 0x00,  (byte) 0x30,
		(byte) 0x82,  (byte) 0x01,  (byte) 0x0A,  (byte) 0x02,  (byte) 0x82,  (byte) 0x01,  (byte) 0x01,  (byte) 0x00,  (byte) 0xB7,  (byte) 0x92,  (byte) 0x8B,  (byte) 0xD8,  (byte) 0xCD,  (byte) 0x77,  (byte) 0x99,  (byte) 0x7D,
		(byte) 0xF1,  (byte) 0x9D,  (byte) 0x53,  (byte) 0x4F,  (byte) 0xB1,  (byte) 0xDB,  (byte) 0xC6,  (byte) 0x50,  (byte) 0x22,  (byte) 0xD9,  (byte) 0xAB,  (byte) 0xD7,  (byte) 0xB0,  (byte) 0x40,  (byte) 0xA3,  (byte) 0x0C,
		(byte) 0x05,  (byte) 0xD5,  (byte) 0xCB,  (byte) 0xBB,  (byte) 0x69,  (byte) 0x7D,  (byte) 0xA4,  (byte) 0xC3,  (byte) 0xDA,  (byte) 0x92,  (byte) 0xF1,  (byte) 0xA9,  (byte) 0x8C,  (byte) 0x06,  (byte) 0x14,  (byte) 0x5A,
		(byte) 0x2E,  (byte) 0xF6,  (byte) 0x1F,  (byte) 0x4B,  (byte) 0xAD,  (byte) 0x70,  (byte) 0x9E,  (byte) 0xA2,  (byte) 0x84,  (byte) 0xE7,  (byte) 0x60,  (byte) 0xBE,  (byte) 0x83,  (byte) 0xDA,  (byte) 0xE0,  (byte) 0x0A,
		(byte) 0xC0,  (byte) 0x3C,  (byte) 0xE5,  (byte) 0x32,  (byte) 0xE9,  (byte) 0xF1,  (byte) 0x5D,  (byte) 0xB9,  (byte) 0xCC,  (byte) 0xBC,  (byte) 0x4C,  (byte) 0xA2,  (byte) 0x17,  (byte) 0xAB,  (byte) 0x89,  (byte) 0x13,
		(byte) 0xE8,  (byte) 0x16,  (byte) 0x88,  (byte) 0x32,  (byte) 0xD5,  (byte) 0x8F,  (byte) 0xE2,  (byte) 0xA3,  (byte) 0x62,  (byte) 0xE7,  (byte) 0x2B,  (byte) 0x1B,  (byte) 0x0A,  (byte) 0x12,  (byte) 0x94,  (byte) 0x7A,
		(byte) 0x3A,  (byte) 0xE8,  (byte) 0x2D,  (byte) 0x8C,  (byte) 0x61,  (byte) 0xCE,  (byte) 0xC2,  (byte) 0x8F,  (byte) 0x42,  (byte) 0xEC,  (byte) 0x58,  (byte) 0x20,  (byte) 0xA8,  (byte) 0x9E,  (byte) 0xE9,  (byte) 0xEC,
		(byte) 0x84,  (byte) 0x66,  (byte) 0xCF,  (byte) 0xD3,  (byte) 0x89,  (byte) 0x94,  (byte) 0xBB,  (byte) 0xC1,  (byte) 0xEB,  (byte) 0xF0,  (byte) 0x6E,  (byte) 0x27,  (byte) 0xC9,  (byte) 0xE9,  (byte) 0xF8,  (byte) 0x7D,
		(byte) 0x9D,  (byte) 0x5D,  (byte) 0x53,  (byte) 0xC1,  (byte) 0xDA,  (byte) 0x18,  (byte) 0x05,  (byte) 0x5B,  (byte) 0x7E,  (byte) 0xE4,  (byte) 0xBB,  (byte) 0x78,  (byte) 0x49,  (byte) 0xAC,  (byte) 0xBE,  (byte) 0x57,
		(byte) 0xC9,  (byte) 0x11,  (byte) 0x45,  (byte) 0x23,  (byte) 0x32,  (byte) 0xF6,  (byte) 0x2B,  (byte) 0x7D,  (byte) 0xED,  (byte) 0x8B,  (byte) 0xDD,  (byte) 0xE1,  (byte) 0x82,  (byte) 0xDF,  (byte) 0xDC,  (byte) 0xE6,
		(byte) 0x93,  (byte) 0xC8,  (byte) 0x56,  (byte) 0x02,  (byte) 0x0C,  (byte) 0x2F,  (byte) 0x8B,  (byte) 0x55,  (byte) 0x63,  (byte) 0x99,  (byte) 0x27,  (byte) 0x87,  (byte) 0xE4,  (byte) 0xE7,  (byte) 0x90,  (byte) 0x2A,
		(byte) 0xAA,  (byte) 0x42,  (byte) 0xEE,  (byte) 0xCA,  (byte) 0xCD,  (byte) 0xCD,  (byte) 0xD2,  (byte) 0x75,  (byte) 0x79,  (byte) 0x94,  (byte) 0x37,  (byte) 0xEA,  (byte) 0xF7,  (byte) 0x41,  (byte) 0xEF,  (byte) 0xF0,
		(byte) 0x90,  (byte) 0xC3,  (byte) 0x0A,  (byte) 0x5F,  (byte) 0x53,  (byte) 0x67,  (byte) 0x30,  (byte) 0xE5,  (byte) 0x28,  (byte) 0x72,  (byte) 0x16,  (byte) 0x48,  (byte) 0xD7,  (byte) 0x33,  (byte) 0x49,  (byte) 0x92,
		(byte) 0xDE,  (byte) 0x74,  (byte) 0xC8,  (byte) 0x05,  (byte) 0xF3,  (byte) 0x31,  (byte) 0x36,  (byte) 0x01,  (byte) 0x55,  (byte) 0xA6,  (byte) 0x63,  (byte) 0x52,  (byte) 0x2E,  (byte) 0x0E,  (byte) 0x12,  (byte) 0xFD,
		(byte) 0x31,  (byte) 0xBE,  (byte) 0x26,  (byte) 0x70,  (byte) 0x13,  (byte) 0x3A,  (byte) 0x68,  (byte) 0x7D,  (byte) 0x57,  (byte) 0x80,  (byte) 0xF4,  (byte) 0xA6,  (byte) 0x84,  (byte) 0x3F,  (byte) 0x00,  (byte) 0x10,
		(byte) 0xB4,  (byte) 0x09,  (byte) 0x2D,  (byte) 0xCF,  (byte) 0xC6,  (byte) 0xDC,  (byte) 0x6D,  (byte) 0x79,  (byte) 0x60,  (byte) 0xA9,  (byte) 0x55,  (byte) 0x5B,  (byte) 0x1D,  (byte) 0x6B,  (byte) 0x4C,  (byte) 0x92,
		(byte) 0x43,  (byte) 0x30,  (byte) 0x90,  (byte) 0x42,  (byte) 0x80,  (byte) 0x59,  (byte) 0x60,  (byte) 0x7D,  (byte) 0x02,  (byte) 0x03,  (byte) 0x01,  (byte) 0x00,  (byte) 0x01
	};
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

				System.out.print("Validating certificate request public key... ");
				NharuRSAPublicKey pubkey = request.getPublicKey();
				if (!NharuArrays.equals(pubkey.getEncoded(), PUBKEY)) throw new RuntimeException("Could not validate certificate request public key");
				System.out.println("Done!");

				System.out.print("Validating certificate request signature... ");
				request.verify();
				System.out.println("Done!");
			}
			finally { request.releaseObject(); }
		}
		catch (Exception e) { e.printStackTrace(); }
	}
}