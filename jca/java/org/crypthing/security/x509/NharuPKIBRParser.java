package org.crypthing.security.x509;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.crypthing.util.NharuArrays;

/**
 * Parses ICP-Brasil Subject Alternative Names exclusive other names.
 * @author magut
 *
 */
public final class NharuPKIBRParser
{
	/**
	 * Certificate type according 7.1.2.3 item of DOC-ICP-04.
	 * @author magut
	 *
	 */
	public enum PKIBRCertificateType
	{
		Undefined(0),
		PF(1),
		PJ(2),
		URL(3),
		NonPKIBR(4);

		final private int _type;
		private PKIBRCertificateType(final int type) { _type = type; }
		public int getType() { return _type; }
		static PKIBRCertificateType certificateTypeByConst(final int type)
		{
			switch (type)
			{
			case 1: return PF;
			case 2: return PJ;
			case 3: return URL;
			case 4: return NonPKIBR;
			default: throw new IllegalArgumentException();
			}
		}
	}

	/**
	 * Get a ICP-Brasil certificate parser.
	 * @param cert - the certificate itself.
	 * @return an instance of parser.
	 * @throws CertificateException - if the parsing process fails.
	 */
	public static NharuPKIBRParser parse(final X509Certificate cert) throws CertificateException
	{
		if (cert == null) throw new CertificateException(new NullPointerException());
		if (!(cert instanceof NharuX509Certificate)) return new NharuPKIBRParser(NharuX509Factory.generateCertificate(cert.getEncoded()));
		return new NharuPKIBRParser((NharuX509Certificate) cert);
	}

	private long hHandle;
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObjectNoData() throws ObjectStreamException { throw new NotSerializableException(); }

	private byte[] _encoding;
	private int _hash;
	private PKIBRCertificateType _type = PKIBRCertificateType.Undefined;
	private char[] _subject_id;
	private char[] _sponsor_name;
	private char[] _company_id;
	private char[] _sponsor_id;
	private char[] _subject_te;
	private char[] _subject_cei;
	private char[] _company_cei;
	private char[] _company_name;
	private NharuPKIBRParser(final NharuX509Certificate cert) throws CertificateException
	{
		hHandle = nhixPKIBRParseNode(cert.getCertificateHandle());
	}
	private NharuPKIBRParser(final byte[] extension) throws CertificateException
	{
		hHandle = nhixPKIBRParseEncoding(extension);
		_encoding = extension;
	}
	private NharuPKIBRParser()
	{
		hHandle = 0;
	}

	@Override
	public String toString()
	{
		char[] value;
		final StringBuilder builder = new StringBuilder();
		builder.append("OID 2.16.76.1.3.1: ");
		value = getSubjectId();
		if (value != null) builder.append(value);
		builder.append(", OID 2.16.76.1.3.2: ");
		value = getSponsorName();
		if (value != null) builder.append(value);
		builder.append(", OID 2.16.76.1.3.3: ");
		value = getCompanyId();
		if (value != null) builder.append(value);
		builder.append(", OID 2.16.76.1.3.4: ");
		value = getSponsorId();
		if (value != null) builder.append(value);
		builder.append(", OID 2.16.76.1.3.5: ");
		value = getSubjectTE();
		if (value != null) builder.append(value);
		builder.append(", OID 2.16.76.1.3.6: ");
		value = getSubjectCEI();
		if (value != null)  builder.append(value);
		builder.append(", OID 2.16.76.1.3.7: ");
		value = getCompanyCEI();
		if (value != null) builder.append(value);
		builder.append(", OID 2.16.76.1.3.8: ");
		value = getCompanyName();
		if (value != null) builder.append(value);
		return builder.toString();
	}

	@Override
	public boolean equals(final Object other)
	{
		if (this == other) return true;
		if (other instanceof NharuPKIBRParser)
		{
			final byte[] thisEncoding = getEncoding();
			final byte[] otherEncoding = ((NharuPKIBRParser) other).getEncoding();
			return NharuArrays.equals(thisEncoding, otherEncoding);
		}
		return false;
	}

	byte[] getEncoding()
	{
		if (_encoding == null)
		{
			if (hHandle != 0) _encoding = nhixPKIBRGetEncoding(hHandle);
		}
		return _encoding;
	}

	@Override
	public int hashCode()
	{
		if (_hash == 0)
		{
			final byte[] encoding = getEncoding();
			if (encoding != null) _hash = NharuArrays.hashCode(encoding);
		}
		return _hash;
	}

	/**
	 * This method MUST be called after use
	 */
	public void releaseParser()
	{
		if (hHandle != 0) nhixPKIBRReleaseHandle(hHandle);
		hHandle = 0;
	}

	/**
	 * Get this certificate type (according to 7.1.2.3 section of DOC-ICP-04).
	 * @return the proper type identification.
	 */
	public PKIBRCertificateType getCertificateType()
	{
		if (_type == PKIBRCertificateType.Undefined)
		{
			if (hHandle != 0) _type = PKIBRCertificateType.certificateTypeByConst(nhixPKIBRGetType(hHandle));
			else _type = PKIBRCertificateType.NonPKIBR;
		}
		return _type;
	}

	/**
	 * Get the content of other name 2.16.76.1.3.1, if present.
	 * @return the content itself or null, if the extension is not present.
	 */
	public char[] getSubjectId()
	{
		if (_subject_id == null)
		{
			if (hHandle != 0) _subject_id = nhixPKIBRGetSubjectId(hHandle);
		}
		return _subject_id;
	}

	/**
	 * Get the content of other name 2.16.76.1.3.2, if present.
	 * @return the content itself or null, if the extension is not present.
	 */
	public char[] getSponsorName()
	{
		if (_sponsor_name == null)
		{
			if (hHandle != 0) _sponsor_name = nhixPKIBRGetSponsorName(hHandle);
		}
		return _sponsor_name;
	}

	/**
	 * Get the content of other name 2.16.76.1.3.3, if present.
	 * @return the content itself or null, if the extension is not present.
	 */
	public char[] getCompanyId()
	{
		if (_company_id == null)
		{
			if (hHandle != 0) _company_id = nhixPKIBRGetCompanyId(hHandle);
		}
		return _company_id;
	}

	/**
	 * Get the content of other name 2.16.76.1.3.4, if present.
	 * @return the content itself or null, if the extension is not present.
	 */
	public char[] getSponsorId()
	{
		if (_sponsor_id == null)
		{
			if (hHandle != 0) _sponsor_id = nhixPKIBRGetSponsorId(hHandle);
		}
		return _sponsor_id;
	}

	/**
	 * Get the content of other name 2.16.76.1.3.5, if present.
	 * @return the content itself or null, if the extension is not present.
	 */
	public char[] getSubjectTE()
	{
		if (_subject_te == null)
		{
			if (hHandle != 0) _subject_te = nhixPKIBRGetSubjectTE(hHandle);
		}
		return _subject_te;
	}

	/**
	 * Get the content of other name 2.16.76.1.3.6, if present.
	 * @return the content itself or null, if the extension is not present.
	 */
	public char[] getSubjectCEI()
	{
		if (_subject_cei == null)
		{
			if (hHandle != 0) _subject_cei = nhixPKIBRGetSubjectCEI(hHandle);
		}
		return _subject_cei;
	}

	/**
	 * Get the content of other name 2.16.76.1.3.7, if present.
	 * @return the content itself or null, if the extension is not present.
	 */
	public char[] getCompanyCEI()
	{
		if (_company_cei == null)
		{
			if (hHandle != 0) _company_cei = nhixPKIBRGetCompanyCEI(hHandle);
		}
		return _company_cei;
	}

	/**
	 * Get the content of other name 2.16.76.1.3.8, if present.
	 * @return the content itself or null, if the extension is not present.
	 */
	public char[] getCompanyName()
	{
		if (_company_name == null)
		{
			if (hHandle != 0) _company_name = nhixPKIBRGetCompanyName(hHandle);
		}
		return _company_name;
	}

	native long nhixPKIBRParseNode(long handle) throws CertificateException;
	native long nhixPKIBRParseEncoding(byte[] encoding) throws CertificateException;
	native void nhixPKIBRReleaseHandle(long handle);
	native byte[] nhixPKIBRGetEncoding(long handle);
	native int nhixPKIBRGetType(long handle);
	native char[] nhixPKIBRGetSubjectId(long handle);
	native char[] nhixPKIBRGetSponsorName(long handle);
	native char[] nhixPKIBRGetCompanyId(long handle);
	native char[] nhixPKIBRGetSponsorId(long handle);
	native char[] nhixPKIBRGetSubjectTE(long handle);
	native char[] nhixPKIBRGetSubjectCEI(long handle);
	native char[] nhixPKIBRGetCompanyCEI(long handle);
	native char[] nhixPKIBRGetCompanyName(long handle);



	
	/*
	 * Basic tests
	 * ==================================
	 */
	private static final byte[] PF_CERT =
	(
		"-----BEGIN CERTIFICATE-----\n" + 
		"MIIE5jCCA86gAwIBAgIBADANBgkqhkiG9w0BAQsFADByMQswCQYDVQQGEwJCUjET\n" + 
		"MBEGA1UEChMKUEtJIEJyYXppbDEfMB0GA1UECxMWUEtJIFJ1bGVyIGZvciBBbGwg\n" + 
		"Q2F0czEtMCsGA1UEAxMkQ29tbW9uIE5hbWUgZm9yIEFsbCBDYXRzIEVuZCBVc2Vy\n" + 
		"IENBMB4XDTE1MTIyMTE2NTQ0NFoXDTE2MTIyMDE2NTQ0NFowWzELMAkGA1UEBhMC\n" + 
		"QlIxEzARBgNVBAoTClBLSSBCcmF6aWwxHzAdBgNVBAsTFlBLSSBSdWxlciBmb3Ig\n" + 
		"QWxsIENhdHMxFjAUBgNVBAMTDUZ1bGFubyBkZSBUYWwwggEiMA0GCSqGSIb3DQEB\n" + 
		"AQUAA4IBDwAwggEKAoIBAQDOPlYYYTdgFwdYTeyIrkbIO+cHQKZCUAzYSHNMwAn4\n" + 
		"2Cq8LtUzdLKhZcIEYQr/fNWXsYkJNs2IfagaMsqMyfuBsgfO3R0gJAvf/qkxomxu\n" + 
		"XS8dtS3+L76JbLx6yhuTFbWYiJyFYZf8naFHOEDKpCu37zck5GJYvDlNVKjk4zfa\n" + 
		"uyRXOkfsQEDLH4Fxpxk6tl94OsTI+pFHG6bRGeC0Cv4TUHA3oV4+M11ynP2yrgWt\n" + 
		"FlnpAn393RpZ7gJXecTgsF6g8QmkEuvdCzmT8T/IyxewUDGzWEB+W/JphBVVlzgJ\n" + 
		"IhdZToDJTQM0V1cfV8kM34edgbKY4NRjw2BWVJc/UN6XAgMBAAGjggGcMIIBmDAJ\n" + 
		"BgNVHRMEAjAAMB0GA1UdDgQWBBSHun2hxdxaQ70DktTSy6Te6LmRQDAfBgNVHSME\n" + 
		"GDAWgBRcJue8Izy1Mr+HxMNFoa5sESpQCDALBgNVHQ8EBAMCBeAwKQYDVR0lBCIw\n" + 
		"IAYIKwYBBQUHAwIGCCsGAQUFBwMEBgorBgEEAYI3FAICMCwGA1UdHwQlMCMwIaAf\n" + 
		"oB2GG2h0dHA6Ly9sb2NhbGhvc3QvYWMvZW5kLmNybDA4BggrBgEFBQcBAQQsMCow\n" + 
		"KAYIKwYBBQUHMAKGHGh0dHA6Ly9sb2NhbGhvc3QvYWMvZW5kLmh0bWwwdQYDVR0R\n" + 
		"BG4wbKA4BgVgTAEDAaAvBC0xMTExMTkxMTExMTExMTExMTExMDAwMDAwMDAwMDAw\n" + 
		"MDAwMDAwMDAwMDAwMDCgFwYFYEwBAwWgDgQMMDAwMDAwMDAwMDAwoBcGBWBMAQMG\n" + 
		"oA4EDDAwMDAwMDAwMDAwMDA0BgNVHSAELTArMCkGAysFCDAiMCAGCCsGAQUFBwIB\n" + 
		"FhRodHRwOi8vbXkuaG9zdC5uYW1lLzANBgkqhkiG9w0BAQsFAAOCAQEAXrRGcn62\n" + 
		"42wO13guy3kgnxSkc1lsW5ccw38xbks115Hbf25n1BPXW35dP08evAm2lqBjGf7j\n" + 
		"khKSwE4sxL5RKK6y/y8/D3Yzr1RzdDqKYLc9PlOdomISvhsC6eUZ2h3LCjscMCsX\n" + 
		"OCs3qPVYcjmran76LY5wygZmRmTojhczTPlHErjnK9XMf0k/JM9yE81qlpeNiZp/\n" + 
		"iuImUfGlwMSlrc6uMOQRcNepksWLTWaz9SWdCEuQEoOpn5V0beKC4SWtfFTV5DTG\n" + 
		"jP87R+m4Pt23y/NDVA3Y/q16h87M3zYlLerHUj96YdZ+7FDc2WqTCggduDVaGko5\n" + 
		"D3HPIqzrUsIT+w==" + 
		"-----END CERTIFICATE-----"
	).getBytes();
	private static final char[] subject_id = "111119111111111111100000000000000000000000000".toCharArray();
	private static final char[] subject_te = "000000000000".toCharArray();
	private static final char[] subject_cei = "000000000000".toCharArray();

	private static void testFields(final NharuPKIBRParser parser)
	{
		if (parser.getCertificateType() == PKIBRCertificateType.PF) System.out.println("Certificate type validated");
		else System.err.println("Certificate type validation failed");
		if (Arrays.equals(parser.getSubjectId(), subject_id)) System.out.println("Subject ID validated");
		else System.err.println("Subject ID validation failed");
		if (Arrays.equals(parser.getSubjectTE(), subject_te)) System.out.println("Subject TE validated");
		else System.err.println("Subject TE validation failed");
		if (Arrays.equals(parser.getSubjectCEI(), subject_cei)) System.out.println("Subject CEI validated");
		else System.err.println("Subject CEI validation failed");
	}
	private static void basicTest()
	{
		System.out.println("NharuPKIBRParser basic test");
		try
		{
			final NharuX509Certificate endCert = new NharuX509Certificate(PF_CERT);
			try
			{
				final NharuPKIBRParser parser = NharuPKIBRParser.parse(endCert);
				try { testFields(parser); }
				finally { parser.releaseParser(); }
			}
			finally { endCert.closeHandle(); }
		}
		catch (final Throwable e) { e.printStackTrace(); }
		System.out.println("NharuPKIBRParser basic test done");
	}
	private static void compatibilityTest()
	{
		System.out.println("NharuPKIBRParser compatibility test");
		try
		{
			final CertificateFactory cf = CertificateFactory.getInstance("X.509");
			final X509Certificate sunCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(PF_CERT));
			final NharuPKIBRParser parser = NharuPKIBRParser.parse(sunCert);
			try { testFields(parser); }
			finally { parser.releaseParser(); }
		}
		catch (final Throwable e) { e.printStackTrace(); }
		System.out.println("NharuPKIBRParser compatibility test done");
	}
	public static void main(final String[] args)
	{
		basicTest();
		compatibilityTest();
	}
}