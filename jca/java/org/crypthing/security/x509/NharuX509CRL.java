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
import java.security.cert.CRLException;
import java.security.cert.CRLReason;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.TimeZone;

import javax.security.auth.x500.X500Principal;

import org.crypthing.security.NharuRSAPublicKey;
import org.crypthing.security.provider.NharuProvider;
import org.crypthing.util.NharuArrays;
import org.crypthing.util.NharuCommon;

public class NharuX509CRL extends X509CRL
{
	static { NharuProvider.isLoaded(); }

	/*
	 * CRL parsing native handle.
	 * This means that NharuX509CRL must not be serialiazed.
	 */
	private long hHandle;
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws NotSerializableException { throw new NotSerializableException(); }
	private void readObjectNoData() throws ObjectStreamException { throw new NotSerializableException(); }

	private byte[] encoding = null;
	private Date nextUpdate = null;
	private Date thisUpdate = null;
	private String signatureAlgorithm = null;
	private String sigOID = null;
	private byte[] sigAlgParams = null;
	private byte[] signature = null;
	private byte[] tbsCertList = null;
	private int version = -1;
	private Set<String> criticalExtensions = null;
	private Set<String> nonCriticalExtensions = null;
	private String thisString = null;
	private int hash = 0;
	private X500Principal issuer = null;
	private BigInteger crlNumber = null;
	private NharuX509Name encodedIssuer = null;
	private Set<X509CRLEntry> revoked = null;

	public NharuX509CRL(final byte[] encoding) throws CRLException
	{
		/*
		 * We need to do this call due to java.security.cert.CRL implementation.
		 * This class has a good example of an abstract class with a final method!
		 * Holy shit!
		 */
		super();
		if (encoding == null) throw new CRLException("CRL encoding must not be null", new NullPointerException());
		hHandle = nhixParseCRL(encoding);
	}

	/**
	 * MUST call this method when CRL is no longer needed.
	 * Remember: all returned NharuCRLEntry objects are also released.
	 */
	public synchronized void closeHandle()
	{
		if (hHandle != 0)
		{
			nhixReleaseCRL(hHandle);
			hHandle = 0;
		}
	}


	/*
	 * * * * * * * * * * * * * * * * * * * * *
	 * X509CRL abstract methods implementation
	 * * * * * * * * * * * * * * * * * * * * *
	 */
	@Override
	public byte[] getEncoded() throws CRLException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (encoding == null) encoding = nhixGetEncoded(hHandle);
		return encoding;
	}

	@Override
	public Principal getIssuerDN()
	{
		return getIssuerX500Principal();
	}

	@Override
	public Date getNextUpdate()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (nextUpdate == null)
		{
			long next = nhixGetNextUpdate(hHandle);
			if (next != 0)
			{
				final Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
				cal.setTimeInMillis(next);
				nextUpdate = cal.getTime();
			}
		}
		return nextUpdate;
	}

	@Override
	public X509CRLEntry getRevokedCertificate(final BigInteger serialNumber)
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (serialNumber == null) throw new NullPointerException("Serial number must not be null");
		return new NharuCRLEntry(getCRLHandle(), nhixGetRevoked(hHandle, serialNumber.toByteArray()));
	}

	@Override
	public Set<? extends X509CRLEntry> getRevokedCertificates()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (revoked == null) revoked  = nhixGetRevokedCertificates(hHandle); 
		return revoked;
	}

	@Override
	public String getSigAlgName()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (signatureAlgorithm == null) signatureAlgorithm = NharuCommon.getAlgorithmName(nhixGetSignatureMechanism(hHandle));
		return signatureAlgorithm;
	}

	@Override
	public String getSigAlgOID()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (sigOID == null) sigOID = NharuCommon.oidToString(nhixGetSignatureMechanismOID(hHandle));
		return sigOID;
	}

	@Override
	public byte[] getSigAlgParams()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (sigAlgParams  == null) sigAlgParams = nhixGetSignatureAlgParameters(hHandle);
		return sigAlgParams;
	}

	@Override
	public byte[] getSignature()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (signature == null) signature = nhixGetSignature(hHandle);
		return signature ;
	}

	@Override
	public byte[] getTBSCertList() throws CRLException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (tbsCertList  == null) tbsCertList = nhixGetTBSCertList(hHandle);
		return tbsCertList;
	}

	@Override
	public Date getThisUpdate()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (thisUpdate == null)
		{
			final Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
			cal.setTimeInMillis(nhixGetThisUpdate(hHandle));
			thisUpdate = cal.getTime();
		}
		return thisUpdate;
	}

	@Override
	public int getVersion()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (version < 0) version = nhixGetVersion(hHandle);
		return version;
	}

	@Override
	public void verify(final PublicKey key) throws CRLException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
	{
		verify(key, (String) null);
	}

	@Override
	public void verify(final PublicKey key, final String sigProvider) throws CRLException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (key == null) throw new CRLException("Argument key must not be null.", new NullPointerException());
		// TODO: Must support ECDSA
		if
		(
			key instanceof NharuRSAPublicKey &&
			(sigProvider == null || NharuProvider.NHARU_PROVIDER_NAME.equalsIgnoreCase(sigProvider))
		)	nhixVerify(hHandle, ((NharuRSAPublicKey) key).getInternalNode());
		else
		{
			final byte[] tbs = getTBSCertList();
			final String algorithm = getSigAlgName();
			final byte[] sig = getSignature();
			final Signature verify = (sigProvider == null) ? Signature.getInstance(algorithm) : Signature.getInstance(algorithm, sigProvider);
			verify.initVerify(key);
			verify.update(tbs);
			if (!verify.verify(sig)) throw new SignatureException("Signature does not match.");
		}
	}



	/*
	 * * * * * * * * * * * * * * * * * * * * * * * * *
	 * java.security.cert.X509Extension implementation
	 * * * * * * * * * * * * * * * * * * * * * * * * *
	 */
	@Override
	public Set<String> getCriticalExtensionOIDs()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (criticalExtensions  == null)
		{
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
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (oid == null) throw new NullPointerException("Argument oid must not be null.");
		byte[] ret = null;
		final int[] id = NharuCommon.stringToOID(oid);
		if (id != null) ret = nhixGetExtension(hHandle, id);
		return ret;
	}

	@Override
	public Set<String> getNonCriticalExtensionOIDs()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (nonCriticalExtensions == null)
		{
			final Set<int[]> set = nhixGetNonCriticalExtensionOIDs(hHandle);
			final Set<String> tmp = new HashSet<>(set.size());
			final Iterator<int[]> it = set.iterator();
			while (it.hasNext()) tmp.add(NharuCommon.oidToString(it.next()));
			nonCriticalExtensions = Collections.unmodifiableSet(tmp);
		}
		return nonCriticalExtensions;
	}
	@Override public boolean hasUnsupportedCriticalExtension() { return false; }



	/*
	 * * * * * * * * * * * * * * * * * * * *
	 * java.security.cert.CRL implementation
	 * * * * * * * * * * * * * * * * * * * *
	 */
	@Override
	public boolean isRevoked(final Certificate cert)
	{
		if (cert == null) throw new NullPointerException("Certificate argument must not be null");
		byte[] serial;
		if (cert instanceof NharuX509Certificate) serial = ((NharuX509Certificate) cert).getSerial();
		else if (cert instanceof X509Certificate) serial = ((X509Certificate) cert).getSerialNumber().toByteArray();
		else
		{
			try { serial = NharuX509Factory.generateCertificate(cert.getEncoded()).getSerial(); }
			catch (final CertificateException e) { return false; }
		}
		return isRevoked(serial);
	}

	@Override
	public String toString()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (thisString == null)
		{
			final StringBuilder builder = new StringBuilder(512);
			builder.append("CRL issued by ");
			builder.append(getIssuerX500Principal().getName());
			builder.append(" at ");
			builder.append(getThisUpdate().toString());
			thisString = builder.toString();
		}
		return thisString;
	}



	/*
	 * * * * * * * * * * * * * * * * * * * * * * *
	 * java.security.cert.X509CRL reimplementation
	 * due to circular dependency.
	 * O my Lord, my sweet Lord...
	 * * * * * * * * * * * * * * * * * * * * * * *
	 */
	@Override
	public boolean equals(final Object other)
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (this == other) return true;
		if (!(other instanceof NharuX509CRL)) return false;
		try { return NharuArrays.equals(getEncoded(), ((NharuX509CRL) other).getEncoded());
		} catch (final CRLException e) { return false; }
	}

	@Override
	public int hashCode()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (hash == 0)
		{
			try { hash = NharuArrays.hashCode(getEncoded()); }
			catch (final CRLException e) { /* swallowed */ }
		}
		return hash;
	}

	@Override
	public X500Principal getIssuerX500Principal()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (issuer == null) issuer  = new X500Principal(nhixGetIssuer(hHandle));
		return issuer;
	}

	@Override
	public X509CRLEntry getRevokedCertificate(final X509Certificate certificate)
	{
		return getRevokedCertificate(certificate.getSerialNumber());
	}

	
	/*
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 * Non-standard interface
	 * Used the verify revocation in a network service context.
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 */
	public boolean isRevoked(final byte[] serialNumber)
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (serialNumber == null) throw new NullPointerException("Certificate serial number must not be NULL");
		return nhixIsRevoked(hHandle, serialNumber);
	}

	public NharuX509Name getIssuer()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (encodedIssuer == null)
		{
			encodedIssuer = new NharuX509Name(nhixGetIssuerName(hHandle));
		}
		return encodedIssuer;
	}

	long getCRLHandle()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		return hHandle;
	}


	/*
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 * Native methods
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 */
	private static native long nhixParseCRL(byte[] encoding) throws CRLException;
	private static native void nhixReleaseCRL(long handle);
	private static native byte[] nhixGetEncoded(long handle)  throws CRLException;
	private static native long nhixGetNextUpdate(long handle);
	private static native long nhixGetThisUpdate(long handle);
	private static native boolean nhixIsRevoked(long handle, byte[] serialNumber);
	private static native int nhixGetSignatureMechanism(long handle);
	private static native int[] nhixGetSignatureMechanismOID(long handle);
	private static native byte[] nhixGetSignatureAlgParameters(long handle);
	private static native byte[] nhixGetSignature(long handle);
	private static native byte[] nhixGetTBSCertList(long handle) throws CRLException;
	private static native int nhixGetVersion(long handle);
	private static native void nhixVerify(long crlHandle, long keyHandle) throws CRLException, SignatureException;
	private static native byte[] nhixGetExtension(long handle, int[] oid);
	private static native byte[] nhixGetIssuer(long handle);
	private static native String nhixGetIssuerName(long handle);
	private static native Set<int[]> nhixGetCriticalExtensionOIDs(long handle);
	private static native Set<int[]> nhixGetNonCriticalExtensionOIDs(long handle);
	private static native long nhixGetRevoked(long handle, byte[] serial);
	private static native Set<X509CRLEntry> nhixGetRevokedCertificates(long handle);



	/*
	 * Basic tests
	 * ==================================
	 */
	private static final String PFV2_CRL =
		"-----BEGIN X509 CRL-----\n" +
		"MIIDgzCCAWsCAQEwDQYJKoZIhvcNAQENBQAwXTELMAkGA1UEBhMCQlIxEzARBgNV\n" +
		"BAoMCklDUC1CcmFzaWwxIDAeBgNVBAsMF0NhaXhhIEVjb25vbWljYSBGZWRlcmFs\n" +
		"MRcwFQYDVQQDDA5BQyBDQUlYQSBQRiB2MhcNMTUxMTAzMTEyNTA3WhcNMTYwNzEw\n" +
		"MTEyNTA3WjBSMCcCCHyXlSH1Hk6bFw0xNDA2MDMxNDA5MDdaMAwwCgYDVR0VBAMK\n" +
		"AQEwJwIIVL+/vi7vvYkXDTEzMTExOTEyMTEzMFowDDAKBgNVHRUEAwoBAaCBhTCB\n" +
		"gjAfBgNVHSMEGDAWgBSVFkagJskQ0byeQ65lhHuiKfxpwzALBgNVHRQEBAICB0Ew\n" +
		"UgYIKwYBBQUHAQEERjBEMEIGCCsGAQUFBzAChjZodHRwOi8vY2VydGlmaWNhZG9k\n" +
		"aWdpdGFsLmNhaXhhLmdvdi5ici9haWEvYWNjYWl4YS5wN2IwDQYJKoZIhvcNAQEN\n" +
		"BQADggIBALGIFUBfKXCMQ/UzG8f3SX/HJn7rmqongC3mp1ueykOrxtdRgVXLHjSs\n" +
		"JKt6tPzO03NMfXEXGTXlYe0XPo7MwC95NGU9SL3bKsT3mPIIo21Giw94P374BfoK\n" +
		"eRhM591z22EgF2xcA/cXR3DwGZtC63GT6YtbfD2magSNF+ky851CMWqnhtjp7o7/\n" +
		"+4SI5+ssqhb4nsB3tC6kYimG6LfqjJRW6UcCSoAQ0eTRw1chqrHgv4gyu+9fQctA\n" +
		"XKDQotehjUWtQ931jPYlyWjG+x5272aiONMvCRJgwCOUFx1C9nMEA4RlL6dHmW3G\n" +
		"VvS5Tt2AZoI2IOBoWIVvsjBsUY6fezR7ddYCCHUxMNQMqL6aXmfgcG+HKgvpr6T+\n" +
		"D/tqLU2IenEPOuBuEeVTagk0z1blIrOJxxMhLaL2F9bxCxUZYvz2wcbsNu35Jip7\n" +
		"iIo81hSZSGWOEbZp4Ghp8KG1E4Pplg0RErpUDWc6rrXT803ILWuqInx81gw3YPk7\n" +
		"/uK6kcO3S439OX3ozBtQsRgzVuob2Gj59+j7dZvtknUaZhPUsIwDrm/O3xl6IqJ7\n" +
		"TmlIoT1P1rxXEorG/DOwW/blOK90OkiTfnyGX+BCU+xCb6vqvLc4+jci0ZV9aaJJ\n" +
		"qflvIMotpzXHdnWq10ikp79PDJrBHq10kAbDL+fV8Sx8AAKNngW4\n" +
		"-----END X509 CRL-----";
	private static final String PFV2_CER =
		"-----BEGIN CERTIFICATE-----\n" +
		"MIIHhDCCBWygAwIBAgIITolitvSUJswwDQYJKoZIhvcNAQENBQAwbjELMAkGA1UE\n" +
		"BhMCQlIxEzARBgNVBAoMCklDUC1CcmFzaWwxNDAyBgNVBAsMK0F1dG9yaWRhZGUg\n" +
		"Q2VydGlmaWNhZG9yYSBSYWl6IEJyYXNpbGVpcmEgdjIxFDASBgNVBAMMC0FDIENB\n" +
		"SVhBIHYyMB4XDTEzMDgzMDE5MTMzMVoXDTIzMDgyODE5MDE0M1owXTELMAkGA1UE\n" +
		"BhMCQlIxEzARBgNVBAoMCklDUC1CcmFzaWwxIDAeBgNVBAsMF0NhaXhhIEVjb25v\n" +
		"bWljYSBGZWRlcmFsMRcwFQYDVQQDDA5BQyBDQUlYQSBQRiB2MjCCAiIwDQYJKoZI\n" +
		"hvcNAQEBBQADggIPADCCAgoCggIBALS+1WRQ4KmJA+RRKw9nPubQpUYTMQvbd0Qi\n" +
		"Qi6Ic2oTpDpqVIiBKNly4KF43TiCfXq1uViJfRnBdYLv3+2EPV94QujdsRiCCpfm\n" +
		"Ubcspsm0yCokHfnIsi9/uJPez5OmJ/r1HPX8AsuIgkQiNPxsBRoWxdyp2ZqWl2OT\n" +
		"1op7KsCGuytxWj4UvuxYXtuXotyUWYPckUA2kYyL+7hCEzdrg7U2+PhITVZYxU2G\n" +
		"TB89YVf5bZv6j9pK+r0PF1/CC2yx1IWIRxaYxG3/5TR3ENozB9MxyfQrm+RfbwlY\n" +
		"JCCMYt/RYTroVmhl25RAynVD6iSztPTvKWupurJkNFsw/fsAG2ua2XdJjR9EJ0FK\n" +
		"oQSb2GpUwRNfmViLNubWQI2NnYotf/oP8jVyzeSO717JBvhoU8444SDzPcdeb5b7\n" +
		"n37086KfGTEPVNWLHC5zNDVZNNCrDDGAWPyAgCH9hrzIuqk1kfUBPWBpfVUYtZRv\n" +
		"K0eTKAUevNLy7xgnNkDE9jkklrUds37HfkGh154BxtQNGDODQ1IQ0+gqODua4dlw\n" +
		"7RYvQoBbihWurd6x0U+LZ4EVQs1yhXBVljfaTPnG21Ggm2ZTEw5TPT+SpRHGmqEp\n" +
		"OctXrOYwNfg63AQ1ts/gPypo6eWWBbxlzkyApjNwrfp7punQyFdwoz2XKdYdU3Rr\n" +
		"VW1Fm6sxAgMBAAGjggI1MIICMTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE\n" +
		"AwIBBjAdBgNVHQ4EFgQUlRZGoCbJENG8nkOuZYR7oin8acMwHwYDVR0jBBgwFoAU\n" +
		"T/OGrWDhMftr317n6jwxFfFvVpAwgcUGA1UdIASBvTCBujBbBgZgTAECAQgwUTBP\n" +
		"BggrBgEFBQcCARZDaHR0cDovL2NlcnRpZmljYWRvZGlnaXRhbC5jYWl4YS5nb3Yu\n" +
		"YnIvZG9jdW1lbnRvcy9kcGNhYy1jYWl4YXBmLnBkZjBbBgZgTAECAwgwUTBPBggr\n" +
		"BgEFBQcCARZDaHR0cDovL2NlcnRpZmljYWRvZGlnaXRhbC5jYWl4YS5nb3YuYnIv\n" +
		"ZG9jdW1lbnRvcy9kcGNhYy1jYWl4YXBmLnBkZjCBsQYDVR0fBIGpMIGmMCugKaAn\n" +
		"hiVodHRwOi8vbGNyLmNhaXhhLmdvdi5ici9hY2NhaXhhdjIuY3JsMCygKqAohiZo\n" +
		"dHRwOi8vbGNyMi5jYWl4YS5nb3YuYnIvYWNjYWl4YXYyLmNybDBJoEegRYZDaHR0\n" +
		"cDovL3JlcG9zaXRvcmlvLmljcGJyYXNpbC5nb3YuYnIvbGNyL0NBSVhBL0FDQ0FJ\n" +
		"WEEvYWNjYWl4YXYyLmNybDBSBggrBgEFBQcBAQRGMEQwQgYIKwYBBQUHMAKGNmh0\n" +
		"dHA6Ly9jZXJ0aWZpY2Fkb2RpZ2l0YWwuY2FpeGEuZ292LmJyL2FpYS9hY2NhaXhh\n" +
		"LnA3YjANBgkqhkiG9w0BAQ0FAAOCAgEAJEYSN4SfSrwhMAfQFzzREmwOQmxOI9Xw\n" +
		"7KajpkoVBmGRfFCybQMaxTMc6ZxpTAHeA3H08qPWVCGpmtq8v8JJiG9dGF8TuntS\n" +
		"K178Xa1X27q91PnQqrYKtHfpHDq3IuvflQhFegHwxpov29MRo8tlNPxL7Gx276nJ\n" +
		"ydzhhoUE65m57wRx2Plv1uffS0QLwT2Sl4h25fExGVAerco0Fn6qLiWVdBOIzny3\n" +
		"Esu31EGWttPZ3XGKNIQ3LpbslNN7YQIpytNxk2AlrEhZrTagJM2ZDDIRnvLQBPbI\n" +
		"T2rmPGZNAJlePDxzODk8uFpU6XtSm9Zo/Z6omyo6rYOdQtq0e+BR8h9AIZClnTHW\n" +
		"2cJI87/AOtRgSE5Mlp8G0BxcK3EYzYkRgrJ6P+u3r5fYW7nWsrfGAyrf1h0QNdeV\n" +
		"MuXwcW30ayoEkx4b6i0OmEEyFdscYIobRzf8/SrRjDPtS5z3f/zatVSJiWSOH5RQ\n" +
		"z4ldlqNjSASh2zXRXAx1MKQtalOhhR1YINRttBr/Dlr8DQSHUsqSm1kG7/zGZEM4\n" +
		"Ft4slgwEpLLHv5pkLu68UJZ0SNYuwPY6OCd0Hnj60DLlscUig3GLLoWawhAyTx8b\n" +
		"FXEtM7REtv8Oay6ZyZiAkBWyOM9A3zZbFcDEOatQG8VOqpAB6Iz50hp0TykUqlb7\n" +
		"PoxXROPqH64=\n" +
		"-----END CERTIFICATE-----";
	private static final String NEXT_UPDATE = "160710112507Z";
	private static final String THIS_UPDATE = "151103112507Z";
	private static final byte[] REVOKED_SERIAL = { (byte) 0x7C, (byte) 0x97, (byte) 0x95, (byte) 0x21, (byte) 0xF5, (byte) 0x1E, (byte) 0x4E, (byte) 0x9B };
	private static final byte[] VALID_SERIAL = { (byte) 0x7C, (byte) 0x97, (byte) 0x95, (byte) 0x21, (byte) 0xF5, (byte) 0x1E, (byte) 0x4E, (byte) 0x9C };
	private static final String SIG_ALG_NAME = "SHA512withRSA";
	private static final String SIG_ALG_OID = "1.2.840.113549.1.1.13";
	private static final byte[] SIGNATURE =
	{
		(byte) 0xB1, (byte) 0x88, (byte) 0x15, (byte) 0x40, (byte) 0x5F, (byte) 0x29, (byte) 0x70, (byte) 0x8C, (byte) 0x43, (byte) 0xF5, (byte) 0x33, (byte) 0x1B, (byte) 0xC7, (byte) 0xF7, (byte) 0x49, (byte) 0x7F,
		(byte) 0xC7, (byte) 0x26, (byte) 0x7E, (byte) 0xEB, (byte) 0x9A, (byte) 0xAA, (byte) 0x27, (byte) 0x80, (byte) 0x2D, (byte) 0xE6, (byte) 0xA7, (byte) 0x5B, (byte) 0x9E, (byte) 0xCA, (byte) 0x43, (byte) 0xAB,
		(byte) 0xC6, (byte) 0xD7, (byte) 0x51, (byte) 0x81, (byte) 0x55, (byte) 0xCB, (byte) 0x1E, (byte) 0x34, (byte) 0xAC, (byte) 0x24, (byte) 0xAB, (byte) 0x7A, (byte) 0xB4, (byte) 0xFC, (byte) 0xCE, (byte) 0xD3,
		(byte) 0x73, (byte) 0x4C, (byte) 0x7D, (byte) 0x71, (byte) 0x17, (byte) 0x19, (byte) 0x35, (byte) 0xE5, (byte) 0x61, (byte) 0xED, (byte) 0x17, (byte) 0x3E, (byte) 0x8E, (byte) 0xCC, (byte) 0xC0, (byte) 0x2F,
		(byte) 0x79, (byte) 0x34, (byte) 0x65, (byte) 0x3D, (byte) 0x48, (byte) 0xBD, (byte) 0xDB, (byte) 0x2A, (byte) 0xC4, (byte) 0xF7, (byte) 0x98, (byte) 0xF2, (byte) 0x08, (byte) 0xA3, (byte) 0x6D, (byte) 0x46,
		(byte) 0x8B, (byte) 0x0F, (byte) 0x78, (byte) 0x3F, (byte) 0x7E, (byte) 0xF8, (byte) 0x05, (byte) 0xFA, (byte) 0x0A, (byte) 0x79, (byte) 0x18, (byte) 0x4C, (byte) 0xE7, (byte) 0xDD, (byte) 0x73, (byte) 0xDB,
		(byte) 0x61, (byte) 0x20, (byte) 0x17, (byte) 0x6C, (byte) 0x5C, (byte) 0x03, (byte) 0xF7, (byte) 0x17, (byte) 0x47, (byte) 0x70, (byte) 0xF0, (byte) 0x19, (byte) 0x9B, (byte) 0x42, (byte) 0xEB, (byte) 0x71,
		(byte) 0x93, (byte) 0xE9, (byte) 0x8B, (byte) 0x5B, (byte) 0x7C, (byte) 0x3D, (byte) 0xA6, (byte) 0x6A, (byte) 0x04, (byte) 0x8D, (byte) 0x17, (byte) 0xE9, (byte) 0x32, (byte) 0xF3, (byte) 0x9D, (byte) 0x42,
		(byte) 0x31, (byte) 0x6A, (byte) 0xA7, (byte) 0x86, (byte) 0xD8, (byte) 0xE9, (byte) 0xEE, (byte) 0x8E, (byte) 0xFF, (byte) 0xFB, (byte) 0x84, (byte) 0x88, (byte) 0xE7, (byte) 0xEB, (byte) 0x2C, (byte) 0xAA,
		(byte) 0x16, (byte) 0xF8, (byte) 0x9E, (byte) 0xC0, (byte) 0x77, (byte) 0xB4, (byte) 0x2E, (byte) 0xA4, (byte) 0x62, (byte) 0x29, (byte) 0x86, (byte) 0xE8, (byte) 0xB7, (byte) 0xEA, (byte) 0x8C, (byte) 0x94,
		(byte) 0x56, (byte) 0xE9, (byte) 0x47, (byte) 0x02, (byte) 0x4A, (byte) 0x80, (byte) 0x10, (byte) 0xD1, (byte) 0xE4, (byte) 0xD1, (byte) 0xC3, (byte) 0x57, (byte) 0x21, (byte) 0xAA, (byte) 0xB1, (byte) 0xE0,
		(byte) 0xBF, (byte) 0x88, (byte) 0x32, (byte) 0xBB, (byte) 0xEF, (byte) 0x5F, (byte) 0x41, (byte) 0xCB, (byte) 0x40, (byte) 0x5C, (byte) 0xA0, (byte) 0xD0, (byte) 0xA2, (byte) 0xD7, (byte) 0xA1, (byte) 0x8D,
		(byte) 0x45, (byte) 0xAD, (byte) 0x43, (byte) 0xDD, (byte) 0xF5, (byte) 0x8C, (byte) 0xF6, (byte) 0x25, (byte) 0xC9, (byte) 0x68, (byte) 0xC6, (byte) 0xFB, (byte) 0x1E, (byte) 0x76, (byte) 0xEF, (byte) 0x66,
		(byte) 0xA2, (byte) 0x38, (byte) 0xD3, (byte) 0x2F, (byte) 0x09, (byte) 0x12, (byte) 0x60, (byte) 0xC0, (byte) 0x23, (byte) 0x94, (byte) 0x17, (byte) 0x1D, (byte) 0x42, (byte) 0xF6, (byte) 0x73, (byte) 0x04,
		(byte) 0x03, (byte) 0x84, (byte) 0x65, (byte) 0x2F, (byte) 0xA7, (byte) 0x47, (byte) 0x99, (byte) 0x6D, (byte) 0xC6, (byte) 0x56, (byte) 0xF4, (byte) 0xB9, (byte) 0x4E, (byte) 0xDD, (byte) 0x80, (byte) 0x66,
		(byte) 0x82, (byte) 0x36, (byte) 0x20, (byte) 0xE0, (byte) 0x68, (byte) 0x58, (byte) 0x85, (byte) 0x6F, (byte) 0xB2, (byte) 0x30, (byte) 0x6C, (byte) 0x51, (byte) 0x8E, (byte) 0x9F, (byte) 0x7B, (byte) 0x34,
		(byte) 0x7B, (byte) 0x75, (byte) 0xD6, (byte) 0x02, (byte) 0x08, (byte) 0x75, (byte) 0x31, (byte) 0x30, (byte) 0xD4, (byte) 0x0C, (byte) 0xA8, (byte) 0xBE, (byte) 0x9A, (byte) 0x5E, (byte) 0x67, (byte) 0xE0,
		(byte) 0x70, (byte) 0x6F, (byte) 0x87, (byte) 0x2A, (byte) 0x0B, (byte) 0xE9, (byte) 0xAF, (byte) 0xA4, (byte) 0xFE, (byte) 0x0F, (byte) 0xFB, (byte) 0x6A, (byte) 0x2D, (byte) 0x4D, (byte) 0x88, (byte) 0x7A,
		(byte) 0x71, (byte) 0x0F, (byte) 0x3A, (byte) 0xE0, (byte) 0x6E, (byte) 0x11, (byte) 0xE5, (byte) 0x53, (byte) 0x6A, (byte) 0x09, (byte) 0x34, (byte) 0xCF, (byte) 0x56, (byte) 0xE5, (byte) 0x22, (byte) 0xB3,
		(byte) 0x89, (byte) 0xC7, (byte) 0x13, (byte) 0x21, (byte) 0x2D, (byte) 0xA2, (byte) 0xF6, (byte) 0x17, (byte) 0xD6, (byte) 0xF1, (byte) 0x0B, (byte) 0x15, (byte) 0x19, (byte) 0x62, (byte) 0xFC, (byte) 0xF6,
		(byte) 0xC1, (byte) 0xC6, (byte) 0xEC, (byte) 0x36, (byte) 0xED, (byte) 0xF9, (byte) 0x26, (byte) 0x2A, (byte) 0x7B, (byte) 0x88, (byte) 0x8A, (byte) 0x3C, (byte) 0xD6, (byte) 0x14, (byte) 0x99, (byte) 0x48,
		(byte) 0x65, (byte) 0x8E, (byte) 0x11, (byte) 0xB6, (byte) 0x69, (byte) 0xE0, (byte) 0x68, (byte) 0x69, (byte) 0xF0, (byte) 0xA1, (byte) 0xB5, (byte) 0x13, (byte) 0x83, (byte) 0xE9, (byte) 0x96, (byte) 0x0D,
		(byte) 0x11, (byte) 0x12, (byte) 0xBA, (byte) 0x54, (byte) 0x0D, (byte) 0x67, (byte) 0x3A, (byte) 0xAE, (byte) 0xB5, (byte) 0xD3, (byte) 0xF3, (byte) 0x4D, (byte) 0xC8, (byte) 0x2D, (byte) 0x6B, (byte) 0xAA,
		(byte) 0x22, (byte) 0x7C, (byte) 0x7C, (byte) 0xD6, (byte) 0x0C, (byte) 0x37, (byte) 0x60, (byte) 0xF9, (byte) 0x3B, (byte) 0xFE, (byte) 0xE2, (byte) 0xBA, (byte) 0x91, (byte) 0xC3, (byte) 0xB7, (byte) 0x4B,
		(byte) 0x8D, (byte) 0xFD, (byte) 0x39, (byte) 0x7D, (byte) 0xE8, (byte) 0xCC, (byte) 0x1B, (byte) 0x50, (byte) 0xB1, (byte) 0x18, (byte) 0x33, (byte) 0x56, (byte) 0xEA, (byte) 0x1B, (byte) 0xD8, (byte) 0x68,
		(byte) 0xF9, (byte) 0xF7, (byte) 0xE8, (byte) 0xFB, (byte) 0x75, (byte) 0x9B, (byte) 0xED, (byte) 0x92, (byte) 0x75, (byte) 0x1A, (byte) 0x66, (byte) 0x13, (byte) 0xD4, (byte) 0xB0, (byte) 0x8C, (byte) 0x03,
		(byte) 0xAE, (byte) 0x6F, (byte) 0xCE, (byte) 0xDF, (byte) 0x19, (byte) 0x7A, (byte) 0x22, (byte) 0xA2, (byte) 0x7B, (byte) 0x4E, (byte) 0x69, (byte) 0x48, (byte) 0xA1, (byte) 0x3D, (byte) 0x4F, (byte) 0xD6,
		(byte) 0xBC, (byte) 0x57, (byte) 0x12, (byte) 0x8A, (byte) 0xC6, (byte) 0xFC, (byte) 0x33, (byte) 0xB0, (byte) 0x5B, (byte) 0xF6, (byte) 0xE5, (byte) 0x38, (byte) 0xAF, (byte) 0x74, (byte) 0x3A, (byte) 0x48,
		(byte) 0x93, (byte) 0x7E, (byte) 0x7C, (byte) 0x86, (byte) 0x5F, (byte) 0xE0, (byte) 0x42, (byte) 0x53, (byte) 0xEC, (byte) 0x42, (byte) 0x6F, (byte) 0xAB, (byte) 0xEA, (byte) 0xBC, (byte) 0xB7, (byte) 0x38,
		(byte) 0xFA, (byte) 0x37, (byte) 0x22, (byte) 0xD1, (byte) 0x95, (byte) 0x7D, (byte) 0x69, (byte) 0xA2, (byte) 0x49, (byte) 0xA9, (byte) 0xF9, (byte) 0x6F, (byte) 0x20, (byte) 0xCA, (byte) 0x2D, (byte) 0xA7,
		(byte) 0x35, (byte) 0xC7, (byte) 0x76, (byte) 0x75, (byte) 0xAA, (byte) 0xD7, (byte) 0x48, (byte) 0xA4, (byte) 0xA7, (byte) 0xBF, (byte) 0x4F, (byte) 0x0C, (byte) 0x9A, (byte) 0xC1, (byte) 0x1E, (byte) 0xAD,
		(byte) 0x74, (byte) 0x90, (byte) 0x06, (byte) 0xC3, (byte) 0x2F, (byte) 0xE7, (byte) 0xD5, (byte) 0xF1, (byte) 0x2C, (byte) 0x7C, (byte) 0x00, (byte) 0x02, (byte) 0x8D, (byte) 0x9E, (byte) 0x05, (byte) 0xB8
	};
	private static final int VERSION = 2;
	private static final String CRL_NUMBER_OID = "2.5.29.20";
	private static final byte[] CRL_NUMBER = { (byte) 0x04, (byte) 0x04, (byte) 0x02, (byte) 0x02, (byte) 0x07, (byte) 0x41 };
	private static final String[] NON_CRITICAL_OIDS =
	{
		"2.5.29.35",
		"2.5.29.20",
		"1.3.6.1.5.5.7.1.1",
	};
	private static final String REVOCATION_DATE = "140603140907Z";
	private static final CRLReason REVOCATION_REASON = CRLReason.KEY_COMPROMISE;
	private static final String REASON_OID = "2.5.29.21";

	private static void basicTest()
	{
		System.out.println("NharuX509CRL basic test");
		try
		{
			System.out.print("Parsing CRL... ");
			final NharuX509CRL crl = new NharuX509CRL(PFV2_CRL.getBytes());
			System.out.println("Done!");
			try
			{
				System.out.print("Parsing CRL issuer certificate... ");
				final NharuX509Certificate cert = new NharuX509Certificate(PFV2_CER.getBytes());
				System.out.println("Done!");
				try
				{
					System.out.print("Checking issuer principal... ");
					if (!cert.getSubjectX500Principal().equals(crl.getIssuerX500Principal())) throw new RuntimeException("Issuer principal does not match");
					System.out.println("Done!");

					System.out.print("Checking issuer using internal API... ");
					if (!cert.getSubject().equals(crl.getIssuer())) throw new RuntimeException("Issuer does not match");
					System.out.println("Done!");

					System.out.print("Checking issuer signature... ");
					crl.verify(cert.getPublicKey());
					System.out.println("Done!");
				}
				finally { cert.closeHandle(); }

				final DateFormat fmt = new SimpleDateFormat("yyMMddHHmmssX");
				fmt.setCalendar(Calendar.getInstance(TimeZone.getTimeZone("GMT")));
				System.out.print("Checking CRL nextUpdate field... ");
				Date buffer = crl.getNextUpdate();
				if (buffer == null || !NEXT_UPDATE.equals(fmt.format(buffer))) throw new RuntimeException("CRL next update does not match!");
				System.out.println("Done!");

				System.out.print("Checking CRL this field... ");
				if (!THIS_UPDATE.equals(fmt.format(crl.getThisUpdate()))) throw new RuntimeException("CRL this update does not match!");
				System.out.println("Done!");

				System.out.print("Checking revoked certificate serial number... ");
				if (!crl.isRevoked(REVOKED_SERIAL)) throw new RuntimeException("Revoked certificate serial number failed");
				System.out.println("Done!");

				System.out.print("Checking non-revoked certificate serial number... ");
				if (crl.isRevoked(VALID_SERIAL)) throw new RuntimeException("Non-revoked certificate serial number failed");
				System.out.println("Done!");

				System.out.print("Checking signature algorithm name... ");
				if (!SIG_ALG_NAME.equals(crl.getSigAlgName())) throw new RuntimeException("Signature algorithm name does not match");
				System.out.println("Done!");

				System.out.print("Checking signature algorithm OID... ");
				if (!SIG_ALG_OID.equals(crl.getSigAlgOID())) throw new RuntimeException("Signature algorithm OID does not match");
				System.out.println("Done!");

				System.out.print("Checked signature bit string field... ");
				if (!Arrays.equals(SIGNATURE, crl.getSignature())) throw new RuntimeException("Signature bit string field does not match");
				System.out.println("Done!");

				System.out.print("Checking certificate version... ");
				if (crl.getVersion() != VERSION) throw new RuntimeException("Certificate version does not match");
				System.out.println("Done!");

				System.out.print("Checking CRLNumber extension... ");
				final byte[] ext = crl.getExtensionValue(CRL_NUMBER_OID);
				if (ext == null || !Arrays.equals(CRL_NUMBER, ext)) throw new RuntimeException("CRLNumber extension does not match");
				System.out.println("Done!");

				System.out.print("Checking critical extensions... ");
				Set<String> oids = crl.getCriticalExtensionOIDs();
				if (oids == null || !oids.isEmpty()) throw new RuntimeException("Critical extensions do not match");
				System.out.println("Done!");

				System.out.print("Checking non-critical extensions... ");
				oids = crl.getNonCriticalExtensionOIDs();
				if (oids == null) throw new RuntimeException("Non-critical extensions do not match");
				for (int i = 0; i < NON_CRITICAL_OIDS.length; i++) if (!oids.contains(NON_CRITICAL_OIDS[i])) throw new RuntimeException("Non-critical extensions do not match");
				System.out.println("Done!");

				System.out.print("Parsing X509CRLEntry... ");
				final X509CRLEntry entry = crl.getRevokedCertificate(new BigInteger(REVOKED_SERIAL));
				System.out.println("Done!");

				System.out.print("Checking revocation date... ");
				if (!REVOCATION_DATE.equals(fmt.format(entry.getRevocationDate()))) throw new RuntimeException("Revocation date does not match");
				System.out.println("Done!");

				System.out.print("Checking revocation reason... ");
				if (entry.getRevocationReason() != REVOCATION_REASON) throw new RuntimeException("Revocation reason does not match");
				System.out.println("Done!");

				System.out.print("Checking serial number... ");
				if (!Arrays.equals(entry.getSerialNumber().toByteArray(), REVOKED_SERIAL)) throw new RuntimeException("Serial number does not match");
				System.out.println("Done!");

				System.out.print("Checking non-critical OIDs... ");
				if (!entry.getNonCriticalExtensionOIDs().contains(REASON_OID)) throw new RuntimeException("Non-critical OIDs do not match");
				System.out.println("Done!");

				System.out.print("Checking revoked certificates list... ");
				if (!crl.getRevokedCertificates().contains(entry)) throw new RuntimeException("Revoked certificates list does not match");
				System.out.println("Done!");
			}
			finally { crl.closeHandle(); }
		}
		catch (final Throwable e) { e.printStackTrace(); }
	}
	private static void compatibilityTest()
	{
		System.out.println("NharuX509CRL compatibility test");
		try
		{
			final X509CRL sun = (X509CRL) (new sun.security.provider.X509Factory()).engineGenerateCRL(new ByteArrayInputStream(PFV2_CRL.getBytes()));
			final NharuX509CRL nharu = new NharuX509CRL(PFV2_CRL.getBytes());
			try
			{
				final int tests = 19;
				int fail = 0;
				System.out.print("Checking CRL encoding... ");
				if (!Arrays.equals(sun.getEncoded(), nharu.getEncoded()))
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking CRL issuer principal... ");
				if (!sun.getIssuerX500Principal().getName().equals(nharu.getIssuerX500Principal().getName()))
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				final DateFormat fmt = new SimpleDateFormat("yyMMddHHmmssX");
				fmt.setCalendar(Calendar.getInstance(TimeZone.getTimeZone("GMT")));
				System.out.print("Checking CRL next update... ");
				if (!fmt.format(sun.getNextUpdate()).equals(fmt.format(nharu.getNextUpdate())))
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking signature algorithm name... ");
				if (!sun.getSigAlgName().equals(nharu.getSigAlgName()))
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking signature algorithm OID... ");
				if (!sun.getSigAlgOID().equals(nharu.getSigAlgOID()))
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking signature bit string... ");
				if (!Arrays.equals(sun.getSignature(), nharu.getSignature()))
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking TBSCertList... ");
				if (!Arrays.equals(sun.getTBSCertList(), nharu.getTBSCertList()))
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking CRL this update... ");
				if (!fmt.format(sun.getThisUpdate()).equals(fmt.format(nharu.getThisUpdate())))
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking CRL version... ");
				if (sun.getVersion() != nharu.getVersion())
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking CRL Authority Key Identifier extension... ");
				if (!Arrays.equals(sun.getExtensionValue("2.5.29.35"), nharu.getExtensionValue("2.5.29.35")))
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking CRL Number extension... ");
				if (!Arrays.equals(sun.getExtensionValue("2.5.29.20"), nharu.getExtensionValue("2.5.29.20")))
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking CRL Authority Info Access extension... ");
				if (!Arrays.equals(sun.getExtensionValue("1.3.6.1.5.5.7.1.1"), nharu.getExtensionValue("1.3.6.1.5.5.7.1.1")))
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking CRL non-critical extensions OIDs");
				if (sun.getNonCriticalExtensionOIDs().size() != nharu.getNonCriticalExtensionOIDs().size())
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				X509CRLEntry sunEntry = sun.getRevokedCertificate(new BigInteger(REVOKED_SERIAL));
				X509CRLEntry nharuEntry = nharu.getRevokedCertificate(new BigInteger(REVOKED_SERIAL));
				System.out.print("Checking X509CRLEntry encoding... ");
				if (!Arrays.equals(sunEntry.getEncoded(), nharuEntry.getEncoded()))
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking X509CRLEntry revocation date... ");
				if (!fmt.format(sunEntry.getRevocationDate()).equals(fmt.format(nharuEntry.getRevocationDate())))
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking X509CRLEntry revocation reason... ");
				if (sunEntry.getRevocationReason() != nharuEntry.getRevocationReason())
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking X509CRLEntry serial number... ");
				if (!Arrays.equals(sunEntry.getSerialNumber().toByteArray(), nharuEntry.getSerialNumber().toByteArray()))
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking X509CRLEntry extensions... ");
				if (sunEntry.hasExtensions() != nharuEntry.hasExtensions())
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.print("Checking X509CRLEntry list... ");
				if (sun.getRevokedCertificates().size() != nharu.getRevokedCertificates().size())
				{
					System.err.println("Failed!");
					fail++;
				}
				else System.out.println("Done!");

				System.out.println("NharuX509CRL is " + (100 - (100 * fail / tests)) + "% compatible with JDK implementation!");
			}
			finally { nharu.closeHandle(); }
		}
		catch (final Throwable e) { e.printStackTrace(); }
	}
	public static void main(final String[] args)
	{
		basicTest();
		compatibilityTest();
	}
}