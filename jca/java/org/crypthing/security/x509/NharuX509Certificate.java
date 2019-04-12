package org.crypthing.security.x509;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;

import javax.security.auth.x500.X500Principal;

import org.crypthing.security.EncodingException;
import org.crypthing.security.NharuRSAPublicKey;
import org.crypthing.security.provider.NharuProvider;
import org.crypthing.util.NharuArrays;
import org.crypthing.util.NharuCommon;

/**
 * java.security.cert.X509Certificate native implementation. This implementation
 * is NOT fully compatible with Sun JDK. The methods getIssuerAlternativeNames()
 * and getSubjectAlternativeNames() of both implementations return different DER
 * encodings if referenced GeneralName is an OtherName. JDK implementation does
 * not return DER encoding as is, but alters it's contents, while Nharu
 * implementation does not.
 * 
 * @author magut & dsohsten
 *
 */
public final class NharuX509Certificate extends X509Certificate
{
	static { NharuProvider.isLoaded(); }
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObjectNoData() throws ObjectStreamException { throw new NotSerializableException(); }

	/*
	 * Certificate parsing native handle. This means that NharuX509Certificate
	 * must not be serialiazed.
	 */
	private long hHandle;

	/*
	 * Certificate fields shortcuts. This prevents continuous native calls.
	 */
	private byte[] encoded;
	private int hash;
	private String thisString;
	private PublicKey pubkey;
	private int basicConstraints = Integer.MIN_VALUE;
	private boolean[] issuerUniqueID;
	private boolean[] keyUsage;
	private Date notAfter;
	private Date notBefore;
	private BigInteger serialNumber;
	private String sigAlg;
	private String sigOID;
	private byte[] sigAlgParams;
	private byte[] signature;
	private boolean[] subjectUniqueID;
	private byte[] tbsCertificate;
	private int version;
	private Set<String> criticalExtensions;
	private Set<String> nonCriticalExtensions;
	private X500Principal issuer;
	private X500Principal subject;
	private List<String> extendedKeyUsage;
	private Collection<List<?>> subjectAltNames;
	private Collection<List<?>> issuerAltNames;
	private NharuX509Name encodedIssuer;
	private NharuX509Name encodedSubject;
	private byte[] serial;

	private final byte[] encoding;
	private long cota;

	public NharuX509Certificate(final byte[] encoding) throws CertificateException
	{
		super();
		if (encoding == null)
			throw new CertificateException("Certificate encoding must not be null", new NullPointerException());
		hHandle = nhixParseCertificate(encoding);
		this.encoding = encoding;
		cota = 1;
	}

	public NharuX509Certificate(final long handle)
	{
		hHandle = handle;
		encoding = nhixGetEncoded(hHandle);
	}

	/*
	 * * * * * * * * * * * * * * * * * java.lang.Object implementation * * * *
	 * * * * * * * * * * * * *
	 */
	@Override
	public String toString()
	{
		cota++;
		if (thisString == null)
		{
			final StringBuilder builder = new StringBuilder(512);
			builder.append("Certificate issued to ").append(getSubjectX500Principal().getName()).append(" by CA ")
					.append(getIssuerX500Principal().getName()).append(" with serial number ")
					.append(getSerialNumber().toString());
			thisString = builder.toString();
		}
		return thisString;
	}

	@Override
	public boolean equals(final Object other)
	{
		cota++;
		if (this == other) return true;
		if (!(other instanceof NharuX509Certificate)) return false;
		return NharuArrays.equals(getEncoded(), ((NharuX509Certificate) other).getEncoded());
	}

	@Override
	public int hashCode()
	{
		cota++;
		if (hash == 0)
		{
			if (hHandle == 0) recallHandle();
			hash = NharuArrays.hashCode(getEncoded());
		}
		return hash;
	}

	/*
	 * * * * * * * * * * * * * * * * * * * * * * * *
	 * java.security.cert.Certificate implementation * * * * * * * * * * * * *
	 * * * * * * * * * * *
	 */
	@Override
	public byte[] getEncoded()
	{
		cota++;
		if (encoded == null)
		{
			if (hHandle == 0) recallHandle();
			encoded = nhixGetEncoded(hHandle);
		}
		return encoded;
	}

	@Override public void verify(final PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException { verify(key, (String) null); }
	@Override
	public void verify(final PublicKey key, final String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
	{
		cota++;
		if (key == null)
			throw new CertificateException("Argument key must not be null.", new IllegalArgumentException());
		if (key instanceof NharuRSAPublicKey)
		{
			if (hHandle == 0) recallHandle();
			nhixVerify(hHandle, ((NharuRSAPublicKey) key).getInternalNode());
		}
		else
		{
			final byte[] tbs = getTBSCertificate();
			final String algorithm = getSigAlgName();
			final byte[] sig = getSignature();
			final Signature verify = (sigProvider == null) ? Signature.getInstance(algorithm)
					: Signature.getInstance(algorithm, sigProvider);
			verify.initVerify(key);
			verify.update(tbs);
			if (!verify.verify(sig)) throw new SignatureException("Signature does not match.");
		}
	}

	@Override
	public PublicKey getPublicKey()
	{
		cota++;
		if (pubkey == null)
		{
			final byte[] encoding = nhixGetPubkeyEncoding(hHandle);
			try { pubkey = new NharuRSAPublicKey(encoding); }
			catch (EncodingException e) { throw new RuntimeException(e); }
		}
		return pubkey;
	}

	
	/* * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 * java.securtity.cert.X509Certificate abstract methods
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 */
	@Override
	public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException
	{
		checkValidity(Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTime());
	}

	@Override
	public void checkValidity(final Date instant) throws CertificateExpiredException, CertificateNotYetValidException
	{
		cota++;
		if (instant == null) throw new NullPointerException("Argument instant must not be null");
		if (hHandle == 0) recallHandle();
		nhixCheckValidity(hHandle, instant.getTime());
	}

	@Override
	public int getBasicConstraints()
	{
		cota++;
		if (basicConstraints == Integer.MIN_VALUE)
		{
			if (hHandle == 0) recallHandle();
			basicConstraints = nhixGetBasicConstraints(hHandle);
		}
		return basicConstraints;
	}

	@Override
	public Principal getIssuerDN()
	{
		return getIssuerX500Principal();
	}

	@Override
	public boolean[] getIssuerUniqueID()
	{
		cota++;
		if (issuerUniqueID == null)
		{
			if (hHandle == 0) recallHandle();
			final byte[] ret = nhixGetIssuerUniqueID(hHandle);
			if (ret != null) issuerUniqueID = NharuCommon.bitmapToBoolArray(ret);
		}
		return issuerUniqueID;
	}

	@Override
	public boolean[] getKeyUsage()
	{
		cota++;
		if (keyUsage == null)
		{
			if (hHandle == 0) recallHandle();
			final byte[] ret = nhixGetKeyUsage(hHandle);
			if (ret != null)
			{
				final boolean[] used = NharuCommon.bitmapToBoolArray(ret);
				if (used.length < 9)
				{
					keyUsage = new boolean[9];
					System.arraycopy(used, 0, keyUsage, 0, used.length);
				}
				else keyUsage = used;
			}
		}
		return keyUsage;
	}

	@Override
	public Date getNotAfter()
	{
		cota++;
		if (notAfter == null)
		{
			if (hHandle == 0) recallHandle();
			final Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
			cal.setTimeInMillis(nhixGetNotAfter(hHandle));
			notAfter = cal.getTime();
		}
		return notAfter;
	}

	@Override
	public Date getNotBefore()
	{
		cota++;
		if (notBefore == null)
		{
			if (hHandle == 0) recallHandle();
			final Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
			cal.setTimeInMillis(nhixGetNotBefore(hHandle));
			notBefore = cal.getTime();
		}
		return notBefore;
	}

	@Override
	public BigInteger getSerialNumber()
	{
		cota++;
		if (serialNumber == null)
		{
			if (hHandle == 0) recallHandle();
			if (serial == null) serial = nhixGetSerialNumber(hHandle);
			serialNumber = new BigInteger(serial);
		}
		return serialNumber;
	}

	@Override
	public String getSigAlgName()
	{
		cota++;
		if (sigAlg == null)
		{
			if (hHandle == 0) recallHandle();
			sigAlg = NharuCommon.getAlgorithmName(nhixGetSignatureMechanism(hHandle));
		}
		return sigAlg;
	}

	@Override
	public String getSigAlgOID()
	{
		cota++;
		if (sigOID == null)
		{
			if (hHandle == 0) recallHandle();
			sigOID = NharuCommon.oidToString(nhixGetSignatureMechanismOID(hHandle));
		}
		return sigOID;
	}

	@Override
	public byte[] getSigAlgParams()
	{
		cota++;
		if (sigAlgParams == null)
		{
			if (hHandle == 0) recallHandle();
			sigAlgParams = nhixGetSignatureAlgParameters(hHandle);
		}
		return sigAlgParams;
	}

	@Override
	public byte[] getSignature()
	{
		cota++;
		if (signature == null)
		{
			if (hHandle == 0) recallHandle();
			signature = nhixGetSignature(hHandle);
		}
		return signature;
	}

	@Override
	public Principal getSubjectDN()
	{
		return getSubjectX500Principal();
	}

	@Override
	public boolean[] getSubjectUniqueID()
	{
		cota++;
		if (subjectUniqueID == null)
		{
			if (hHandle == 0) recallHandle();
			final byte[] ret = nhixGetSubjectUniqueID(hHandle);
			if (ret != null) subjectUniqueID = NharuCommon.bitmapToBoolArray(ret);
		}
		return subjectUniqueID;
	}

	@Override
	public byte[] getTBSCertificate() throws CertificateEncodingException
	{
		cota++;
		if (tbsCertificate == null)
		{
			if (hHandle == 0) recallHandle();
			tbsCertificate = nhixGetTBSCertificate(hHandle);
		}
		return tbsCertificate;
	}

	@Override
	public int getVersion()
	{
		cota++;
		if (version == 0)
		{
			if (hHandle == 0) recallHandle();
			version = nhixGetVersion(hHandle);
		}
		return version;
	}


	/* * * * * * * * * * * * * * * * * * * * * * * * * *
	 * java.security.cert.X509Extension implementation
	 * * * * * * * * * * * * * * * * * * * * * * * * * *
	 */
	@Override
	public Set<String> getCriticalExtensionOIDs()
	{
		cota++;
		if (criticalExtensions == null)
		{
			if (hHandle == 0) recallHandle();
			final Set<int[]> set = nhixGetCriticalExtensionOIDs(hHandle);
			final Set<String> tmp = new HashSet<>(set.size());
			final Iterator<int[]> it = set.iterator();
			while (it.hasNext()) tmp.add(NharuCommon.oidToString(it.next()));
			criticalExtensions = Collections.unmodifiableSet(tmp);
		}
		return criticalExtensions;
	}

	@Override
	public byte[] getExtensionValue(final String oid)
	{
		cota++;
		if (oid == null) throw new NullPointerException("Argument oid must not be null.");
		byte[] ret = null;
		final int[] id = NharuCommon.stringToOID(oid);
		if (id != null)
		{
			if (hHandle == 0) recallHandle();
			ret = nhixGetExtension(hHandle, id);
		}
		return ret;
	}

	@Override
	public Set<String> getNonCriticalExtensionOIDs()
	{
		cota++;
		if (nonCriticalExtensions == null)
		{
			if (hHandle == 0) recallHandle();
			final Set<int[]> set = nhixGetNonCriticalExtensionOIDs(hHandle);
			final Set<String> tmp = new HashSet<>(set.size());
			final Iterator<int[]> it = set.iterator();
			while (it.hasNext()) tmp.add(NharuCommon.oidToString(it.next()));
			nonCriticalExtensions = Collections.unmodifiableSet(tmp);
		}
		return nonCriticalExtensions;
	}

	@Override
	public boolean hasUnsupportedCriticalExtension()
	{
		cota++;
		return false;
	}


	/* * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 * Overriden java.security.cert.X509Certificate methods.
	 * This methods call sun.security.x509.X509CertImpl!
	 * Good God!!!
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 */
	@Override
	public X500Principal getIssuerX500Principal()
	{
		cota++;
		if (issuer == null)
		{
			if (hHandle == 0) recallHandle();
			issuer = new X500Principal(nhixGetIssuer(hHandle));
		}
		return issuer;
	}

	@Override
	public X500Principal getSubjectX500Principal()
	{
		cota++;
		if (subject == null)
		{
			if (hHandle == 0) recallHandle();
			subject = new X500Principal(nhixGetSubject(hHandle));
		}
		return subject;
	}

	@Override
	public List<String> getExtendedKeyUsage() throws CertificateParsingException
	{
		cota++;
		if (extendedKeyUsage == null)
		{
			if (hHandle == 0) recallHandle();
			final List<int[]> list = nhixGetExtendedKeyUsage(hHandle);
			if (list != null)
			{
				final List<String> tmp = new ArrayList<>(list.size());
				for (int i = 0; i < list.size(); i++) tmp.add(NharuCommon.oidToString(list.get(i)));
				extendedKeyUsage = Collections.unmodifiableList(tmp);
			}
			
		}
		return extendedKeyUsage;
	}

	@Override
	public Collection<List<?>> getSubjectAlternativeNames()  throws CertificateParsingException
	{
		cota++;
		if (subjectAltNames == null)
		{
			if (hHandle == 0) recallHandle();
			final Collection<List<?>> tmp = nhixGetSubjectAltNames(hHandle);
			if (tmp != null) subjectAltNames = Collections.unmodifiableCollection(tmp);
		}
		return subjectAltNames;
	}

	@Override
	public Collection<List<?>> getIssuerAlternativeNames() throws CertificateParsingException
	{
		cota++;
		if (issuerAltNames == null)
		{
			if (hHandle == 0) recallHandle();
			final Collection<List<?>> tmp = nhixGetIssuerAltNames(hHandle);
			if (tmp != null) issuerAltNames = Collections.unmodifiableCollection(tmp);
		}
		return issuerAltNames;
	}


	/* * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 * Non standard methods.
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 */
	/**
	 * Get the native handle to this certificate.
	 * @return the Java representation of the handle.
	 */
	public long getCertificateHandle()
	{
		cota++;
		if (hHandle == 0) recallHandle();
		return hHandle;
	}
	long takeCota() { return --cota; }
	byte[] getOriginalEncoding() { return encoding; }

	/**
	 * Get the issuer of this certificate
	 * @return an optimized (for hash tables) X.509 Name of the certificate issuer.
	 */
	public NharuX509Name getIssuer()
	{
		cota++;
		if (encodedIssuer == null)
		{
			if (hHandle == 0) recallHandle();
			encodedIssuer = new NharuX509Name(nhixGetNameIssuer(hHandle));
		}
		return encodedIssuer;
	}

	/**
	 * Get the subject of this certificate
	 * @return an optimized (for hash tables) X.509 Name of the certificate subject.
	 */
	public NharuX509Name getSubject()
	{
		cota++;
		if (encodedSubject == null)
		{
			if (hHandle == 0) recallHandle();
			encodedSubject = new NharuX509Name(nhixGetNameSubject(hHandle));
		}
		return encodedSubject;
	}

	public byte[] getSerial()
	{
		cota++;
		if (serial == null)
		{
			if (hHandle == 0) recallHandle();
			serial = nhixGetSerialNumber(hHandle);
		}
		return serial;
	}

	synchronized void recallHandle()
	{
		if (hHandle == 0)
		{
			try
			{
				hHandle = nhixParseCertificate(encoding);
				cota = 1;
				NharuX509Factory.cacheGiveBack(this);
			}
			catch (final CertificateException e) { throw new RuntimeException(e); }
		}
	}

	/**
	 * Releases the native certificate handle. Must be called explicitly by object owner
	 */
	public synchronized void closeHandle()
	{
		if (hHandle != 0)
		{
			nhixReleaseCertificate(hHandle);
			hHandle = 0;
		}
	}


	/* * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 * Native methods.
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 */
	private static native long nhixParseCertificate(byte[] encoding) throws CertificateException;
	private static native void nhixReleaseCertificate(long handle);
	private static native byte[] nhixGetEncoded(long handle);
	private static native void nhixVerify(long certHandle, long keyHandle) throws CertificateException, SignatureException;
	private static native void nhixCheckValidity(long handle, long instant) throws CertificateExpiredException, CertificateNotYetValidException;
	private static native byte[] nhixGetIssuerUniqueID(long handle);
	private static native byte[] nhixGetKeyUsage(long handle);
	private static native long nhixGetNotAfter(long handle);
	private static native long nhixGetNotBefore(long handle);
	private static native byte[] nhixGetSerialNumber(long handle);
	private static native int nhixGetSignatureMechanism(long handle);
	private static native int[] nhixGetSignatureMechanismOID(long handle);
	private static native byte[] nhixGetSignatureAlgParameters(long handle);
	private static native byte[] nhixGetSignature(long handle);
	private static native byte[] nhixGetSubjectUniqueID(long handle);
	private static native byte[] nhixGetTBSCertificate(long handle) throws CertificateEncodingException;
	private static native int nhixGetVersion(long handle);
	private static native byte[] nhixGetIssuer(long handle);
	private static native byte[] nhixGetSubject(long handle);
	private static native byte[] nhixGetExtension(long handle, int[] oid);
	private static native int nhixGetBasicConstraints(long handle); 
	private static native Set<int[]> nhixGetCriticalExtensionOIDs(long handle);
	private static native Set<int[]> nhixGetNonCriticalExtensionOIDs(long handle);
	private static native List<int[]> nhixGetExtendedKeyUsage(long handle);
	private static native Collection<List<?>> nhixGetSubjectAltNames(long handle);
	private static native Collection<List<?>> nhixGetIssuerAltNames(long handle);

	private static native String nhixGetNameIssuer(long handle);
	private static native String nhixGetNameSubject(long handle);

	private static native byte[] nhixGetPubkeyEncoding(long handle);


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
	private static final byte[] CA_CERT=
	(
		"-----BEGIN CERTIFICATE-----\n" + 
		"MIIEbDCCA1SgAwIBAgIBADANBgkqhkiG9w0BAQsFADB2MQswCQYDVQQGEwJCUjET\n" + 
		"MBEGA1UEChMKUEtJIEJyYXppbDEfMB0GA1UECxMWUEtJIFJ1bGVyIGZvciBBbGwg\n" + 
		"Q2F0czExMC8GA1UEAxMoQ29tbW9uIE5hbWUgZm9yIEFsbCBDYXRzIEludGVybWVk\n" + 
		"aWF0ZSBDQTAeFw0xNTEyMjExNjU0MzVaFw0xNjEyMjAxNjU0MzVaMHIxCzAJBgNV\n" + 
		"BAYTAkJSMRMwEQYDVQQKEwpQS0kgQnJhemlsMR8wHQYDVQQLExZQS0kgUnVsZXIg\n" + 
		"Zm9yIEFsbCBDYXRzMS0wKwYDVQQDEyRDb21tb24gTmFtZSBmb3IgQWxsIENhdHMg\n" + 
		"RW5kIFVzZXIgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDasCQQ\n" + 
		"mcUUlZoyo63RNFB+/SqSS3rvUXzAF4yTUQp/Fo5gaEBmthHE5H3EvEAwPN+cZGsi\n" + 
		"zTTFRRYvx/pokUb1KtEwc6dkOPEVNRiDZZndJp4jU4iH+/HfUb+QMZaGR5Fpnbjk\n" + 
		"wYSO5o4PdWZEMkA5Ut6SpORoADXWiyLRXthOyN8BfkGU4Ui3R5VeGra4cxulcCxi\n" + 
		"1gkbbermWSWznbqCAXoo90PhRD0oDqULNeK+Po6BqrjmM5gOX22ZBNKB9uj4Gvhe\n" + 
		"jBFszqWWYbIhXg8ooGbQ+32s+1zCM0vszKzvqToxka7iIbh7Vh8nri2wwC/COY6k\n" + 
		"Eh+ZlQ1w27/UJmitAgMBAAGjggEHMIIBAzAdBgNVHQ4EFgQUXCbnvCM8tTK/h8TD\n" + 
		"RaGubBEqUAgwgZgGA1UdIwSBkDCBjYAUMoOFUsS6+Ss0DLiCJ0R+K+4ucEyhcqRw\n" + 
		"MG4xCzAJBgNVBAYTAkJSMRMwEQYDVQQKEwpQS0kgQnJhemlsMR8wHQYDVQQLExZQ\n" + 
		"S0kgUnVsZXIgZm9yIEFsbCBDYXRzMSkwJwYDVQQDEyBDb21tb24gTmFtZSBmb3Ig\n" + 
		"QWxsIENhdHMgUm9vdCBDQYIBADAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjAs\n" + 
		"BgNVHR8EJTAjMCGgH6AdhhtodHRwOi8vbG9jYWxob3N0L2FjL2VuZC5jcmwwDQYJ\n" + 
		"KoZIhvcNAQELBQADggEBAJUKZhMeD1unIaO9Z1jVJscupENrjz7ytnNQayuZap4k\n" + 
		"KWbadIpnwvrPy7IG53XRNlvzMgX0e+jCA+DjrCQ5/hyfSErHzmzfGeniTi/14Otb\n" + 
		"fziVA6lyDbCSeKUudqDbaI8vvyxTHuY1Ue3C7uT9h3Ztlm3kCsuQHH3HSgPsS1mI\n" + 
		"uvJK7FKetk+lrQ8bx5eSmVIcQmzN1NU/t55B+vWMi/0UmW2VdrjHxERqlfw41anD\n" + 
		"KobiZM1rEjOW6QTMHMXXPeXuMgszsHYfzZfVb0/kGiOHuPslv1OcicvzmUr2mFlg\n" + 
		"q5XJH5dzHH9cZBVs0JO91ZKpDiDBDmep/edsM2IM3BE=\n" + 
		"-----END CERTIFICATE-----"
	).getBytes();
	private static final long INSTANT = 1452189843419L;
	private static final int VERSION = 3;
	private static final String SIGOID = "1.2.840.113549.1.1.11";
	private static final String NOT_BEFORE = "151221165444Z";
	private static final String NOT_AFTER = "161220165444Z";
	private static final String[] EXT_KEY_USAGE = { "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.4", "1.3.6.1.4.1.311.20.2.2" };
	private static final boolean[] KEY_USAGE = { true, true, true, false, false, false, false, false, false };
	private static final String SIG_ALG_NAME = "SHA256withRSA";
	private static final byte[] SIGNATURE =
	{
		(byte) 0x5E, (byte) 0xB4, (byte) 0x46, (byte) 0x72, (byte) 0x7E, (byte) 0xB6, (byte) 0xE3, (byte) 0x6C, (byte) 0x0E, (byte) 0xD7, (byte) 0x78, (byte) 0x2E, (byte) 0xCB, (byte) 0x79, (byte) 0x20, (byte) 0x9F,
		(byte) 0x14, (byte) 0xA4, (byte) 0x73, (byte) 0x59, (byte) 0x6C, (byte) 0x5B, (byte) 0x97, (byte) 0x1C, (byte) 0xC3, (byte) 0x7F, (byte) 0x31, (byte) 0x6E, (byte) 0x4B, (byte) 0x35, (byte) 0xD7, (byte) 0x91,
		(byte) 0xDB, (byte) 0x7F, (byte) 0x6E, (byte) 0x67, (byte) 0xD4, (byte) 0x13, (byte) 0xD7, (byte) 0x5B, (byte) 0x7E, (byte) 0x5D, (byte) 0x3F, (byte) 0x4F, (byte) 0x1E, (byte) 0xBC, (byte) 0x09, (byte) 0xB6,
		(byte) 0x96, (byte) 0xA0, (byte) 0x63, (byte) 0x19, (byte) 0xFE, (byte) 0xE3, (byte) 0x92, (byte) 0x12, (byte) 0x92, (byte) 0xC0, (byte) 0x4E, (byte) 0x2C, (byte) 0xC4, (byte) 0xBE, (byte) 0x51, (byte) 0x28,
		(byte) 0xAE, (byte) 0xB2, (byte) 0xFF, (byte) 0x2F, (byte) 0x3F, (byte) 0x0F, (byte) 0x76, (byte) 0x33, (byte) 0xAF, (byte) 0x54, (byte) 0x73, (byte) 0x74, (byte) 0x3A, (byte) 0x8A, (byte) 0x60, (byte) 0xB7,
		(byte) 0x3D, (byte) 0x3E, (byte) 0x53, (byte) 0x9D, (byte) 0xA2, (byte) 0x62, (byte) 0x12, (byte) 0xBE, (byte) 0x1B, (byte) 0x02, (byte) 0xE9, (byte) 0xE5, (byte) 0x19, (byte) 0xDA, (byte) 0x1D, (byte) 0xCB,
		(byte) 0x0A, (byte) 0x3B, (byte) 0x1C, (byte) 0x30, (byte) 0x2B, (byte) 0x17, (byte) 0x38, (byte) 0x2B, (byte) 0x37, (byte) 0xA8, (byte) 0xF5, (byte) 0x58, (byte) 0x72, (byte) 0x39, (byte) 0xAB, (byte) 0x6A,
		(byte) 0x7E, (byte) 0xFA, (byte) 0x2D, (byte) 0x8E, (byte) 0x70, (byte) 0xCA, (byte) 0x06, (byte) 0x66, (byte) 0x46, (byte) 0x64, (byte) 0xE8, (byte) 0x8E, (byte) 0x17, (byte) 0x33, (byte) 0x4C, (byte) 0xF9,
		(byte) 0x47, (byte) 0x12, (byte) 0xB8, (byte) 0xE7, (byte) 0x2B, (byte) 0xD5, (byte) 0xCC, (byte) 0x7F, (byte) 0x49, (byte) 0x3F, (byte) 0x24, (byte) 0xCF, (byte) 0x72, (byte) 0x13, (byte) 0xCD, (byte) 0x6A,
		(byte) 0x96, (byte) 0x97, (byte) 0x8D, (byte) 0x89, (byte) 0x9A, (byte) 0x7F, (byte) 0x8A, (byte) 0xE2, (byte) 0x26, (byte) 0x51, (byte) 0xF1, (byte) 0xA5, (byte) 0xC0, (byte) 0xC4, (byte) 0xA5, (byte) 0xAD,
		(byte) 0xCE, (byte) 0xAE, (byte) 0x30, (byte) 0xE4, (byte) 0x11, (byte) 0x70, (byte) 0xD7, (byte) 0xA9, (byte) 0x92, (byte) 0xC5, (byte) 0x8B, (byte) 0x4D, (byte) 0x66, (byte) 0xB3, (byte) 0xF5, (byte) 0x25,
		(byte) 0x9D, (byte) 0x08, (byte) 0x4B, (byte) 0x90, (byte) 0x12, (byte) 0x83, (byte) 0xA9, (byte) 0x9F, (byte) 0x95, (byte) 0x74, (byte) 0x6D, (byte) 0xE2, (byte) 0x82, (byte) 0xE1, (byte) 0x25, (byte) 0xAD,
		(byte) 0x7C, (byte) 0x54, (byte) 0xD5, (byte) 0xE4, (byte) 0x34, (byte) 0xC6, (byte) 0x8C, (byte) 0xFF, (byte) 0x3B, (byte) 0x47, (byte) 0xE9, (byte) 0xB8, (byte) 0x3E, (byte) 0xDD, (byte) 0xB7, (byte) 0xCB,
		(byte) 0xF3, (byte) 0x43, (byte) 0x54, (byte) 0x0D, (byte) 0xD8, (byte) 0xFE, (byte) 0xAD, (byte) 0x7A, (byte) 0x87, (byte) 0xCE, (byte) 0xCC, (byte) 0xDF, (byte) 0x36, (byte) 0x25, (byte) 0x2D, (byte) 0xEA,
		(byte) 0xC7, (byte) 0x52, (byte) 0x3F, (byte) 0x7A, (byte) 0x61, (byte) 0xD6, (byte) 0x7E, (byte) 0xEC, (byte) 0x50, (byte) 0xDC, (byte) 0xD9, (byte) 0x6A, (byte) 0x93, (byte) 0x0A, (byte) 0x08, (byte) 0x1D,
		(byte) 0xB8, (byte) 0x35, (byte) 0x5A, (byte) 0x1A, (byte) 0x4A, (byte) 0x39, (byte) 0x0F, (byte) 0x71, (byte) 0xCF, (byte) 0x22, (byte) 0xAC, (byte) 0xEB, (byte) 0x52, (byte) 0xC2, (byte) 0x13, (byte) 0xFB
	};
	private static final String SKI_OID = "2.5.29.14";
	private static final byte[] SKI =
	{
		(byte) 0x04, (byte) 0x16,
		(byte) 0x04, (byte) 0x14, (byte) 0x87, (byte) 0xBA, (byte) 0x7D, (byte) 0xA1, (byte) 0xC5, (byte) 0xDC,
		(byte) 0x5A, (byte) 0x43, (byte) 0xBD, (byte) 0x03, (byte) 0x92, (byte) 0xD4, (byte) 0xD2, (byte) 0xCB,
		(byte) 0xA4, (byte) 0xDE, (byte) 0xE8, (byte) 0xB9, (byte) 0x91, (byte) 0x40
	};
	private static final String AKI_OID = "2.5.29.35";
	private static final byte[] AKI =
	{
		(byte) 0x04, (byte) 0x18,
		(byte) 0x30, (byte) 0x16, (byte) 0x80, (byte) 0x14, (byte) 0x5C, (byte) 0x26, (byte) 0xE7, (byte) 0xBC,
		(byte) 0x23, (byte) 0x3C, (byte) 0xB5, (byte) 0x32, (byte) 0xBF, (byte) 0x87, (byte) 0xC4, (byte) 0xC3,
		(byte) 0x45, (byte) 0xA1, (byte) 0xAE, (byte) 0x6C, (byte) 0x11, (byte) 0x2A, (byte) 0x50, (byte) 0x08
	};
	private static final byte[] SUBJECT_ALT_NAMES_0 =
	{
		(byte) 0xA0, (byte) 0x38, (byte) 0x06, (byte) 0x05, (byte) 0x60, (byte) 0x4C, (byte) 0x01, (byte) 0x03,
		(byte) 0x01, (byte) 0xA0, (byte) 0x2F, (byte) 0x04, (byte) 0x2D, (byte) 0x31, (byte) 0x31, (byte) 0x31,
		(byte) 0x31, (byte) 0x31, (byte) 0x39, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31,
		(byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31,
		(byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30,
		(byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30,
		(byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30,
		(byte) 0x30, (byte) 0x30
	};
	private static final String[] NON_CRITICAL_OIDS =
	{
		"2.5.29.19",
		"2.5.29.14",
		"2.5.29.35",
		"2.5.29.15",
		"2.5.29.37",
		"2.5.29.31",
		"1.3.6.1.5.5.7.1.1",
		"2.5.29.17",
		"2.5.29.32"
	};

	private static void basicTest()
	{
		System.out.println("NharuX509Certificate basic test");
		try
		{
			System.out.print("Parsing end user cert... ");
			final NharuX509Certificate endCert = new NharuX509Certificate(PF_CERT);
			System.out.println("Done!");

			try
			{

				System.out.print("Checking certificate validity... ");
				endCert.checkValidity(new Date(INSTANT));
				System.out.println("Done!");

				System.out.print("Parsing CA cert... ");
				final NharuX509Certificate caCert = new NharuX509Certificate(CA_CERT);
				System.out.println("Done!");

				try
				{
					System.out.print("Checking issuer using default API... ");
					if (!endCert.getIssuerX500Principal().equals(caCert.getSubjectX500Principal())) throw new RuntimeException("Certificate issuer does not match");
					System.out.println("Done!");

					System.out.print("Checking issuer using internal API... ");
					if (!endCert.getIssuer().equals(caCert.getSubject())) throw new RuntimeException("Certificate issuer does not match");
					System.out.println("Done!");

					System.out.print("Verifying issuer signature... ");
					endCert.verify(caCert.getPublicKey());
					System.out.println("Done!");

					System.out.print("Checking certificate version... ");
					if (endCert.getVersion() != VERSION) throw new RuntimeException("Certificate version does not match");
					System.out.println("Done!");

					System.out.print("Checking certificate signature OID... ");
					if (!endCert.getSigAlgOID().equals(SIGOID)) throw new RuntimeException("Certificate signature OID does not match");
					System.out.println("Done!");

					System.out.print("Checking certificate signature algorithm parameters... ");
					if (endCert.getSigAlgParams() != null) throw new RuntimeException("Certificate signature algorithm parameters do not match");
					System.out.println("Done!");

					final DateFormat fmt = new SimpleDateFormat("yyMMddHHmmssX");
					fmt.setCalendar(Calendar.getInstance(TimeZone.getTimeZone("GMT")));
					System.out.print("Checking certificate not before field... ");
					if (!NOT_BEFORE.equals(fmt.format(endCert.getNotBefore()))) throw new RuntimeException("Certificate not before does not match!");
					System.out.println("Done!");

					System.out.print("Checking certificate not after field... ");
					if (!NOT_AFTER.equals(fmt.format(endCert.getNotAfter()))) throw new RuntimeException("Certificate not after does not match!");
					System.out.println("Done!");

					System.out.print("Checking BasicConstraints extension... ");
					if (endCert.getBasicConstraints() != -1) throw new RuntimeException("End user certificate BasicConstraints does not match!");
					if (caCert.getBasicConstraints() != Integer.MAX_VALUE) throw new RuntimeException("CA certificate BasicConstraints does not match!");
					System.out.println("Done!");

					System.out.print("Checking Extended Key Usage extension... ");
					final List<String> ext = endCert.getExtendedKeyUsage();
					for (int i = 0; i < ext.size(); i++) if (!ext.get(i).equals(EXT_KEY_USAGE[i])) throw new RuntimeException("Extended key usage extension does not match");
					System.out.println("Done!");

					System.out.print("Checking Key Usage extension... ");
					final boolean[] kusage = endCert.getKeyUsage();
					if (kusage.length != KEY_USAGE.length)  throw new RuntimeException("Key usage extension length does not match");
					for (int i = 0; i < kusage.length; i++) if (kusage[i] != KEY_USAGE[i])  throw new RuntimeException("Key usage extension does not match");
					System.out.println("Done!");

					System.out.print("Checking serial number... ");
					if (!endCert.getSerialNumber().equals(BigInteger.ZERO)) throw new RuntimeException("Serial number does not match");
					System.out.println("Done!");

					System.out.print("Checking signature algorithm name... ");
					if (!SIG_ALG_NAME.equals(endCert.getSigAlgName())) throw new RuntimeException("Signature algorithm name does not match");
					System.out.println("Done!");

					System.out.print("Checking signature bit string... ");
					if (!Arrays.equals(SIGNATURE, endCert.getSignature())) throw new RuntimeException("Signature bit string does not match");
					System.out.println("Done!");

					System.out.print("Checking Subject Key Identifier extension... ");
					byte[] extval = endCert.getExtensionValue(SKI_OID);
					if (!Arrays.equals(SKI, extval)) throw new RuntimeException("Subject Key Identifier does not match");
					System.out.println("Done!");

					System.out.print("Checking Authority Key Identifier extension... ");
					extval = endCert.getExtensionValue(AKI_OID);
					if (!Arrays.equals(AKI, extval)) throw new RuntimeException("Authority Key Identifier does not match");
					System.out.println("Done!");

					System.out.print("Checking Subject Alternative Names extension... ");
					final Collection<List<?>> alt_names = endCert.getSubjectAlternativeNames();
					if (alt_names == null) throw new RuntimeException("Subject Alternative Names extension does not match");
					boolean found = false;
					for (final List<?> name : alt_names)
					{
						if (Arrays.equals((byte[]) name.get(1), SUBJECT_ALT_NAMES_0))
						{
							found = true;
							break;
						}
					}
					if (!found) throw new RuntimeException("Subject Alternative Names extension does not match");
					System.out.println("Done!");

					System.out.print("Checking critical extensions... ");
					Set<String> oids = endCert.getCriticalExtensionOIDs();
					if (oids == null || !oids.isEmpty()) throw new RuntimeException("Critical extensions do not match");
					System.out.println("Done!");

					System.out.print("Checking non-critical extensions... ");
					oids = endCert.getNonCriticalExtensionOIDs();
					if (oids == null) throw new RuntimeException("Non-critical extensions do not match");
					for (int i = 0; i < NON_CRITICAL_OIDS.length; i++) if (!oids.contains(NON_CRITICAL_OIDS[i])) throw new RuntimeException("Non-critical extensions do not match");
					System.out.println("Done!");
					System.out.println("NharuX509Certificate test succeeded!\n");
				}
				finally { caCert.closeHandle(); }
			}
			finally { endCert.closeHandle(); }
		}
		catch (final Throwable e) { e.printStackTrace(); }
	}
	private static void compatibilityTest()
	{
		System.out.println("NharuX509Certificate compatibility test");
		try
		{
			boolean success = true;
			int fail = 0;
			final CertificateFactory cf = CertificateFactory.getInstance("X.509", "SUN");
			final X509Certificate sunCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(PF_CERT));
			final NharuX509Certificate endCert = new NharuX509Certificate(PF_CERT);
			try
			{
				System.out.print("Checking Basic Constraints extension... ");
				if (sunCert.getBasicConstraints() != endCert.getBasicConstraints())
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking Extended Key Usage extension... ");
				final List<String> sunUsage = sunCert.getExtendedKeyUsage();
				final List<String> nhUsage = endCert.getExtendedKeyUsage();
				for (int i = 0; i < sunUsage.size(); i++) if (!nhUsage.contains(sunUsage.get(i)))
				{
					System.err.println("Test failed!");
					fail++;
					success = false;
					break;
				}
				if (success) System.out.println("Done!");

				System.out.print("Checking issuer principal... ");
				if (!sunCert.getIssuerX500Principal().getName().equals(endCert.getIssuerX500Principal().getName()))
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking subject principal... ");
				if (!sunCert.getSubjectX500Principal().getName().equals(endCert.getSubjectX500Principal().getName()))
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking Key Usage extension... ");
				if (!Arrays.equals(sunCert.getKeyUsage(), endCert.getKeyUsage()))
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				final DateFormat fmt = new SimpleDateFormat("yyMMddHHmmssX");
				fmt.setCalendar(Calendar.getInstance(TimeZone.getTimeZone("GMT")));
				System.out.print("Checking Validity/notBefore field... ");
				if (!fmt.format(sunCert.getNotBefore()).equals(fmt.format(endCert.getNotBefore())))
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking Validity/notAfter field... ");
				if (!fmt.format(sunCert.getNotAfter()).equals(fmt.format(endCert.getNotAfter())))
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking serial number field... ");
				if (!sunCert.getSerialNumber().equals(endCert.getSerialNumber()))
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking signature algorithm name... ");
				if (!sunCert.getSigAlgName().equals(endCert.getSigAlgName()))
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking signature algorithm OID... ");
				if (!sunCert.getSigAlgOID().equals(endCert.getSigAlgOID()))
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking signature bitstring... ");
				if (!Arrays.equals(sunCert.getSignature(), endCert.getSignature()))
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking TBSCertificate encoding... ");
				if (!Arrays.equals(sunCert.getTBSCertificate(), endCert.getTBSCertificate()))
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking version field... ");
				if (sunCert.getVersion() != endCert.getVersion())
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking certificate encoding... ");
				if (!Arrays.equals(sunCert.getEncoded(), endCert.getEncoded()))
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking public key encoding... ");
				if (!Arrays.equals(sunCert.getPublicKey().getEncoded(), endCert.getPublicKey().getEncoded()))
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking Subject Alternative Names extension... ");
				final Iterator<List<?>> sunIt = sunCert.getSubjectAlternativeNames().iterator();
				success = true;
				while (sunIt.hasNext() && success)
				{
					final List<?> it = sunIt.next();
					final Collection<List<?>> alt_names = endCert.getSubjectAlternativeNames();
					success = false;
					for (final List<?> name : alt_names)
					{
						if (Arrays.equals((byte[]) it.get(1), (byte[]) name.get(1)))
						{
							success = true;
							break;
						}
					}
				}
				if (!success)
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking Subject Key Identifier extension... ");
				if (!Arrays.equals(sunCert.getExtensionValue("2.5.29.14"), endCert.getExtensionValue("2.5.29.14")))
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking Authority Key Identifier extension... ");
				if (!Arrays.equals(sunCert.getExtensionValue("2.5.29.35"), endCert.getExtensionValue("2.5.29.35")))
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking CRL Distribution Points extension... ");
				if (!Arrays.equals(sunCert.getExtensionValue("2.5.29.31"), endCert.getExtensionValue("2.5.29.31")))
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking AuthorityInfoAccess extension... ");
				if (!Arrays.equals(sunCert.getExtensionValue("1.3.6.1.5.5.7.1.1"), endCert.getExtensionValue("1.3.6.1.5.5.7.1.1")))
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking Certificate Policies extension... ");
				if (!Arrays.equals(sunCert.getExtensionValue("2.5.29.32"), endCert.getExtensionValue("2.5.29.32")))
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking subjectAltName extension... ");
				if (!Arrays.equals(sunCert.getExtensionValue("2.5.29.17"), endCert.getExtensionValue("2.5.29.17")))
				{
					System.err.println("Test failed!");
					fail++;
				}
				else System.out.println("Done!");
				System.out.println("NharuX509Certificate is " + (100 - (100 * fail / 22)) + "% compatible with JDK X509CertImpl!");
			}
			finally { endCert.closeHandle(); }
		}
		catch (final Throwable e) { e.printStackTrace(); }
	}
	public static void main(final String[] args)
	{
		basicTest();
		compatibilityTest();
	}
}
