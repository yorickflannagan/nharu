package org.crypthing.security.cert;

import static org.crypthing.security.LogDevice.LOG_LEVEL;
import static org.crypthing.security.LogDevice.LOG_LEVEL_DEBUG;
import static org.crypthing.security.LogDevice.LOG_LEVEL_INFO;
import static org.crypthing.security.LogDevice.LOG_LEVEL_NONE;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CRLSelector;
import java.security.cert.CertSelector;
import java.security.cert.CertStoreException;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertStoreSpi;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import org.crypthing.security.LogDevice;
import org.crypthing.security.x509.NharuX509CRL;
import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.security.x509.NharuX509Factory;
import org.crypthing.security.x509.NharuX509Name;

/**
 * Implements a trusted certificate store. It may stores an entire PKI.
 * Only CA certificates and one single root CA are allowed.
 * @author magut
 *
 */
public final class NharuCertStore extends CertStoreSpi
{
	private static final String ERROR_INVALID_ARGUMENT = "Parameters must be valid Nharu types";
	private static final String ERROR_INVALID_CHAIN = "An error has occurred while trying to validate certificate chain";
	private static final String MSG_VALID_STORE = "CertStore has been validated";
	private static final LogDevice LOG = new LogDevice(NharuCertStore.class.getName());

	private final TrustedCertStore certStore;
	private final HashMap<NharuX509Name, NharuX509CRL> crlStore = new HashMap<>();
	private final List<NharuX509Certificate> issuers;

	public NharuCertStore(final CertStoreParameters params) throws InvalidAlgorithmParameterException
	{
		super(params);
		if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack();
		if (!(params instanceof DERX509CollectionParams) && !(params instanceof X509CertCollectionParams))
		{
			if (LOG_LEVEL < LOG_LEVEL_NONE) LOG.fatal(ERROR_INVALID_ARGUMENT);
			throw new InvalidAlgorithmParameterException(ERROR_INVALID_ARGUMENT);
		}

		certStore = new TrustedCertStore();
		List<NharuX509Certificate> temp = new ArrayList<>();
		try
		{
			if (params instanceof X509CertCollectionParams)
			{
				final Iterator<NharuX509Certificate> it = ((X509CertCollectionParams) params).iterator();
				while (it.hasNext())
				{
					final NharuX509Certificate cert = it.next();
					certStore.put(cert.getSubject(), cert);
					temp.add(cert);
				}
			}
			else
			{
				final Iterator<byte[]> certs = ((DERX509CollectionParams) params).getCertificates();
				while (certs.hasNext())
				{
					
					final NharuX509Certificate cert = NharuX509Factory.generateCertificate(certs.next());
					certStore.put(cert.getSubject(), cert);
					temp.add(cert);
				}
				final Iterator<byte[]> crls = ((DERX509CollectionParams) params).getCRLs();
				while (crls.hasNext())
				{
					final NharuX509CRL crl = NharuX509Factory.generateCRL(crls.next());
					crlStore.put(crl.getIssuer(), crl);
				}
			}
			certStore.checkChains();
			issuers = Collections.unmodifiableList(temp);
			if (LOG_LEVEL < LOG_LEVEL_INFO) LOG.debug(MSG_VALID_STORE);
		}
		catch (final CertificateException | CertStoreException | CRLException e)
		{
			if (LOG_LEVEL < LOG_LEVEL_NONE) LOG.fatal(ERROR_INVALID_CHAIN, e);
			throw new InvalidAlgorithmParameterException(ERROR_INVALID_CHAIN, e);
		}
	}
	
	public NharuCertStore(final TrustedCertStore store) throws InvalidAlgorithmParameterException
	{
		super(null);
		this.certStore = store;
		try
		{
			certStore.checkChains();
			final List<NharuX509Certificate> temp = new ArrayList<>();
			temp.addAll(certStore.values());
			issuers = Collections.unmodifiableList(temp);
		}
		catch (final CertStoreException e)
		{
			if (LOG_LEVEL < LOG_LEVEL_NONE) LOG.fatal(ERROR_INVALID_CHAIN, e);
			throw new InvalidAlgorithmParameterException(ERROR_INVALID_CHAIN, e);
		}
		
	}

	@Override
	public Collection<? extends Certificate> engineGetCertificates(final CertSelector selector) throws CertStoreException
	{
		final HashSet<Certificate> result = new HashSet<>();
		final Iterator<NharuX509Certificate> it = certStore.values().iterator();
		while (it.hasNext())
		{
			final NharuX509Certificate entry = it.next();
			if (selector != null) if (selector.match(entry)) result.add(entry);
			else result.add(entry);
		}
		return Collections.unmodifiableCollection(result);
	}

	@Override
	public Collection<? extends CRL> engineGetCRLs(final CRLSelector selector) throws CertStoreException
	{
		final HashSet<CRL> result = new HashSet<>();
		final Iterator<NharuX509CRL> it = crlStore.values().iterator();
		while (it.hasNext())
		{
			final NharuX509CRL entry = it.next();
			if (selector != null) if (selector.match(entry)) result.add(entry);
			else result.add(entry);
		}
		return Collections.unmodifiableCollection(result);
	}

	/**
	 * Check if specified certificate is trusted.
	 * @param cert - the certificate to check.
	 * @return true if the certificate was signed by a trusted CA present in the CertStore.
	 */
	public boolean isTrusted(final NharuX509Certificate cert)
	{
		return isTrusted(cert, true);
	}

	public boolean isTrusted(final NharuX509Certificate cert, boolean checkValidity)
	{
		boolean ret = false;
		final NharuX509Certificate entry = certStore.get(cert.getIssuer());
		if (entry != null)
		{
			try
			{
				if (checkValidity) cert.checkValidity();
				cert.verify(entry.getPublicKey());
				ret = true;
			}
			catch (final InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException swallowed) { /* ignored */ }
		}
		return ret;
	}
	public Iterator<NharuX509Certificate> iterator() { return certStore.values().iterator(); }
	public List<NharuX509Certificate> getIssuers() { return issuers; }





	/*
	 * Basic tests
	 * ==================================
	 */
	private static final String ROOT_CA =
		"-----BEGIN CERTIFICATE-----\n" +
		"MIIGqDCCBJCgAwIBAgIIDaoGBNngq/swDQYJKoZIhvcNAQENBQAwgZcxCzAJBgNV\n" +
		"BAYTAkJSMRMwEQYDVQQKDApJQ1AtQnJhc2lsMT0wOwYDVQQLDDRJbnN0aXR1dG8g\n" +
		"TmFjaW9uYWwgZGUgVGVjbm9sb2dpYSBkYSBJbmZvcm1hY2FvIC0gSVRJMTQwMgYD\n" +
		"VQQDDCtBdXRvcmlkYWRlIENlcnRpZmljYWRvcmEgUmFpeiBCcmFzaWxlaXJhIHYy\n" +
		"MB4XDTEzMDgzMDE5MDE0M1oXDTIzMDgyODE5MDE0M1owgZcxCzAJBgNVBAYTAkJS\n" +
		"MRMwEQYDVQQKDApJQ1AtQnJhc2lsMT0wOwYDVQQLDDRJbnN0aXR1dG8gTmFjaW9u\n" +
		"YWwgZGUgVGVjbm9sb2dpYSBkYSBJbmZvcm1hY2FvIC0gSVRJMTQwMgYDVQQDDCtB\n" +
		"dXRvcmlkYWRlIENlcnRpZmljYWRvcmEgUmFpeiBCcmFzaWxlaXJhIHYyMIICIjAN\n" +
		"BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuEnjSw01dBQ6pqNKXE3ycYkD+qY9\n" +
		"pWeFYNwXedA3PMcgU23pJgZeXxwCAOQEsrI7MRaSWGGm3Ca9CS4JkjIfG6BE0hzp\n" +
		"XcxAAjizCfJ3ptuMTtLrsEaIwTZXW0cnn4oFDmBK/7JTCNlJ8f68XvVP+NvbMb8V\n" +
		"U+EusVDmb4i0xfanlox1LSd9b5VBBipqI4SHlxpflw9Q6pJKbL0am60Pak9IwKNB\n" +
		"2n7IqQVIqfnT7kvqx1oZOhhTc8Pg0Z+m2jNxvCLySphiaPLfTGOSR7K0rEvqZULA\n" +
		"qKFjuyzx8+VJgZiZ1T8mMaWCJ4qLm741HTlnOCbPegzEsdG54euOYNiEZbiW8eo9\n" +
		"MFuMeVkhLein9YvfJDLIA29s+DCK81deOtWgXWUEm5TR51LzCghn4NHol/J0SZqx\n" +
		"Hq6+kJHSKknTCEJto3phYT4M6qGC1RUypjIEus8rrrxfoy2jnXe/S5y4m8byVxE8\n" +
		"N3BWJNEbVvL7CTCseuKc9tW1J+KISwYFHZweHVuZO1eoTXE3gUtvL94EX9A5O4XH\n" +
		"FhFlOKPsxpa69XWuydZktaTDiEKBMx8OJckiMkGXGooTEj9tew9LDuQMyzrUq+by\n" +
		"w1AAtu0dB5IQESA0KT9+Gu/rzzeVgAp5I48Zk38jUaXZTokV4wY5dvmeh4noPwWf\n" +
		"JfbmsPx0y2nGpCMCAwEAAaOB9TCB8jAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB\n" +
		"/wQEAwIBBjAdBgNVHQ4EFgQUqYvVgxJIfzbW9+38NyjWcPh8ueIwHwYDVR0jBBgw\n" +
		"FoAUqYvVgxJIfzbW9+38NyjWcPh8ueIwTgYDVR0gBEcwRTBDBgVgTAEBADA6MDgG\n" +
		"CCsGAQUFBwIBFixodHRwOi8vYWNyYWl6LmljcGJyYXNpbC5nb3YuYnIvRFBDYWNy\n" +
		"YWl6LnBkZjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vYWNyYWl6LmljcGJyYXNp\n" +
		"bC5nb3YuYnIvTENSYWNyYWl6djIuY3JsMA0GCSqGSIb3DQEBDQUAA4ICAQCCjo/Y\n" +
		"rHLfMaWGKZ5BSVfHzKbx25VRMtsH1xkrHNeFt9IfGYbgWg739Oe3/dTWqAuKbtb8\n" +
		"ZVMOYL/le0pZoHfg/o1hFGJY8Dx1zQcwjM7ghNj6yhwJFgVUsUvH0TKolaJ2bsKk\n" +
		"A/Ogz+A06OIo2Dg/g3WxSfoAJYPsloFSk9l2wt/C2o7SaPqbsT+3j8S3qx6rBq2o\n" +
		"A+Rjt6bvfzk9Jc1ZuEZ57vs/YOiJPguXIdBEfJ5K0FSK2/dTkSfGMVG5ISo20cr/\n" +
		"hAF2oFDBri5IT1incTWaWazbB0nBcR2wAaLhZD8mdH8uslN9lRuyjaSbU7iLzpJn\n" +
		"FISK6qhrpMkwOe8CCyQIJDY1t8CC6X6cH1UsFaWP/S6kTT0fWzDDpYA4gD8M5MZy\n" +
		"IATxhKaENxaDP7BmC6reHBEIC0+ipkBqYbKycEvQM/WJ+A7oN4R8wXB6kfKM43b2\n" +
		"l174sTa97hoar+nwP+pPlh07KZ5WYnwTdBNRffD4ZGnMmXplWhoY1YbVWb5SntpF\n" +
		"2qmnLnyvzuBVHEAwrpI1iR5yolTemPSUiDJ5r7tChS7L0flHHc2jSycB1mYjsMQh\n" +
		"6PxvPJpA7f/SrWb/aURWN2/GdRFJAZ6lZPHNBkHFq9gJLB30FFXJydqxvf6heILb\n" +
		"ynLLGMMrnnCjwcMsScXbTMA/+SczbYiSZUm83A==\n" +
		"-----END CERTIFICATE-----";
	private static final String INTER_CA =
		"-----BEGIN CERTIFICATE-----\n" +
		"MIIGlTCCBH2gAwIBAgIIFuw5+x+UGAMwDQYJKoZIhvcNAQENBQAwgZcxCzAJBgNV\n" +
		"BAYTAkJSMRMwEQYDVQQKDApJQ1AtQnJhc2lsMT0wOwYDVQQLDDRJbnN0aXR1dG8g\n" +
		"TmFjaW9uYWwgZGUgVGVjbm9sb2dpYSBkYSBJbmZvcm1hY2FvIC0gSVRJMTQwMgYD\n" +
		"VQQDDCtBdXRvcmlkYWRlIENlcnRpZmljYWRvcmEgUmFpeiBCcmFzaWxlaXJhIHYy\n" +
		"MB4XDTEzMDgzMDE5MDU0N1oXDTIzMDgyODE5MDE0M1owbjELMAkGA1UEBhMCQlIx\n" +
		"EzARBgNVBAoMCklDUC1CcmFzaWwxNDAyBgNVBAsMK0F1dG9yaWRhZGUgQ2VydGlm\n" +
		"aWNhZG9yYSBSYWl6IEJyYXNpbGVpcmEgdjIxFDASBgNVBAMMC0FDIENBSVhBIHYy\n" +
		"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsMK3gFdeYCmLxlJXpidd\n" +
		"VeEA/bSj07prLcrWu065I0Sdzs8qnzGKKJmfi/uCH6qnoZV2kcl345EICOsgj+RM\n" +
		"PXvU7i3JAgUAsHzbL1hMH90PAD9Rqv/fhoH+MntcwtFYjzoADfUjaQxnCqcbKmyn\n" +
		"kzuliGthcs1ekfIG/zi9uh7xi2BcXcjED8elzIghmB1oAGwNHbFk5g1gKwh8U9ce\n" +
		"gNEO3jysYcowvvIAJNXHxqAPuUjKN/Nr6v6hZs5NzhR/hc2LgpGJrkVa6VJ8esrt\n" +
		"giTJwLYPEXQPvH6eBhFVLt5RbbIP67faJx4lI0eaHWKtqEDOlifvY2L7UCEMkw05\n" +
		"uJaxouncir0d9TITnJJksoh+3o3HpPJAFbPDsZYVsmgrAqgPPDZ+NUCHApI9q+dt\n" +
		"JHnFTXoxNJ6eWboH25P96RpTHJhQvOJTIX62OQ5fZA2Q54Q6OpNLQRKALF77hPOg\n" +
		"/36WKSpuQc8aqXnZn3YhwqLbD9aT6eMV/lhsp6/Ejw6HEWTkCwD8BNEF7ddqVoPH\n" +
		"rd30gBMn9b6TQ/ZX21YbYEXYrz4yxBT+JkMCFq4DonXdGD3jiD8JLuMvDQozIcrp\n" +
		"qRbksVDIH2in6Jj8qtFn6la5vHnIa94oHw8aamN1xi/PKL1vQhU2azJTf+bFntse\n" +
		"c99BNcBogje4KLQCvO7jjM8CAwEAAaOCAQswggEHMA8GA1UdEwEB/wQFMAMBAf8w\n" +
		"DgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRP84atYOEx+2vfXufqPDEV8W9WkDAf\n" +
		"BgNVHSMEGDAWgBSpi9WDEkh/Ntb37fw3KNZw+Hy54jBjBgNVHSAEXDBaMFgGBWBM\n" +
		"AQEJME8wTQYIKwYBBQUHAgEWQWh0dHA6Ly9jZXJ0aWZpY2Fkb2RpZ2l0YWwuY2Fp\n" +
		"eGEuZ292LmJyL2RvY3VtZW50b3MvZHBjYWMtY2FpeGEucGRmMD8GA1UdHwQ4MDYw\n" +
		"NKAyoDCGLmh0dHA6Ly9hY3JhaXouaWNwYnJhc2lsLmdvdi5ici9MQ1JhY3JhaXp2\n" +
		"Mi5jcmwwDQYJKoZIhvcNAQENBQADggIBABObaOed85oF0i3I2hu6GrsGCNi2H8Km\n" +
		"2IRMRhqDVd6QwuhahtUCTtHPjZPhHe9/KmrAl6/BA6a+Igfz26ffkc1QckSuiPJo\n" +
		"RFBjZapqbdlZ4tdbjIx8Wof1vlvLI9Ftbrr84/UOI+2KcOJEu/Q8TkWuXuWxshdS\n" +
		"spM6H2ULPAjNniVAC8MNEGDcYiGInQtGtRoM4Ii2I7ZAS89cKLnKmKuroOg/IXAr\n" +
		"VHnerwkOJnTKtF7D4RX6Ltbc9FiEqrZ7NqKJqyYEGXsQdu/xqQWbxaN18+btq++I\n" +
		"ahJUPiZlNedmn/oL8453GN0f+zqBXkbiCeurF038ILrdSigMTaglnp9SPnKOcHPV\n" +
		"g3TzfHtRjtO4UneZfRnuIYdtbUBEEkR9mUfBNCKqSvGwEZzv06ovSv4Nqr7zc7vf\n" +
		"W4EXeW3Ed81qtvT8oLADLkMLMkU+wASWcLUEJnlnRKBwJYNQJYaSXTjtJRlzBjLV\n" +
		"WBxi7UDo2MJMqrfOek6QPB282FewEpJKKw+DnI/L86g2M4j8vsmhFp/nPYGbfdRs\n" +
		"nqQT/HAdtsF2Jgnvu/jSV0ck67SuzIYTdRZMn3OeppIg6lsc6Gg2ZQzf8I3jQPP/\n" +
		"JkRj2rcgfrNDtfy/GTelN8emMtPj0sB00h/hvZe6yqyZstsj+B8iQ/0A6Co5sViV\n" +
		"WYCYfWXL6/JC\n" +
		"-----END CERTIFICATE-----";
	private static final String FINAL_CA =
		"-----BEGIN CERTIFICATE-----\n" +
		"MIIHhDCCBWygAwIBAgIILtC1fcy6ZrgwDQYJKoZIhvcNAQENBQAwbjELMAkGA1UE\n" +
		"BhMCQlIxEzARBgNVBAoMCklDUC1CcmFzaWwxNDAyBgNVBAsMK0F1dG9yaWRhZGUg\n" +
		"Q2VydGlmaWNhZG9yYSBSYWl6IEJyYXNpbGVpcmEgdjIxFDASBgNVBAMMC0FDIENB\n" +
		"SVhBIHYyMB4XDTEzMDgzMDE5MjQ0OVoXDTIzMDgyODE5MDE0M1owXTELMAkGA1UE\n" +
		"BhMCQlIxEzARBgNVBAoMCklDUC1CcmFzaWwxIDAeBgNVBAsMF0NhaXhhIEVjb25v\n" +
		"bWljYSBGZWRlcmFsMRcwFQYDVQQDDA5BQyBDQUlYQSBQSiB2MjCCAiIwDQYJKoZI\n" +
		"hvcNAQEBBQADggIPADCCAgoCggIBAKQq8tKfTYQwSOTtRntqKpJxAZ5wsQG2lrjW\n" +
		"ATAXkD0lDC2943d+b9EA0WZtQ5NGRk1nrh1ZZX6i0q9+kc78KufOcEznC1B6jM7q\n" +
		"hQTc6e7a4LVkC0Q7TUatqaHN/2QAeq9Dqrn3s6wIzbNTdRF9v8tds/FymLRfeCDM\n" +
		"4QQtm4RpVKaPLc/sazTqN6EerIqDuDMoblM+NZ00tIUiJYQ/zsjVb3v2bC+OCjiz\n" +
		"XAhC4suPzeNbm1sw7+uDwc/H84uuae6/zgyBRtl1hVM3FGo+yqxUEXvstL/eNR1l\n" +
		"/jRKwAOaJ9Y6GxW3NnSNlzq72g9J5hIuQfm8H4oG+t4zVPkFNrXADRH/NIvLM5xP\n" +
		"pYjFd+APyn8UnSsM0etcCYPu8NshmHJBeqF8hZWSafCzV6ElDfeaATYlTlCYtEmh\n" +
		"UQYaFQzrNbY/y/Z0hDPpfaoWPW15nLFcQEWncutjtRUGC0gPXimg1inBpl4Zzket\n" +
		"n0hW8neRQ59wFph6yuwrVBEMMSrEt5OXPRP7xnMAGHHDFDGTKIuYyLSbB4boAtLo\n" +
		"EqtH6vudwpt+rVjLe9ZCzE9JrweBnH04+BgavW8Vts/UgvyLKm9ilDBNuLhPPewM\n" +
		"puPiwnNzUReiNMnSsafaCZROEDSWgzKxi4sH1mQYOTkM9JaJkgWP5Qu/YO79qGdB\n" +
		"bTyDpFIFAgMBAAGjggI1MIICMTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE\n" +
		"AwIBBjAdBgNVHQ4EFgQUYT8ejYHTngZxnis+8MS5hMjL3WMwHwYDVR0jBBgwFoAU\n" +
		"T/OGrWDhMftr317n6jwxFfFvVpAwgcUGA1UdIASBvTCBujBbBgZgTAECAQkwUTBP\n" +
		"BggrBgEFBQcCARZDaHR0cDovL2NlcnRpZmljYWRvZGlnaXRhbC5jYWl4YS5nb3Yu\n" +
		"YnIvZG9jdW1lbnRvcy9kcGNhYy1jYWl4YXBqLnBkZjBbBgZgTAECAwkwUTBPBggr\n" +
		"BgEFBQcCARZDaHR0cDovL2NlcnRpZmljYWRvZGlnaXRhbC5jYWl4YS5nb3YuYnIv\n" +
		"ZG9jdW1lbnRvcy9kcGNhYy1jYWl4YXBqLnBkZjCBsQYDVR0fBIGpMIGmMCugKaAn\n" +
		"hiVodHRwOi8vbGNyLmNhaXhhLmdvdi5ici9hY2NhaXhhdjIuY3JsMCygKqAohiZo\n" +
		"dHRwOi8vbGNyMi5jYWl4YS5nb3YuYnIvYWNjYWl4YXYyLmNybDBJoEegRYZDaHR0\n" +
		"cDovL3JlcG9zaXRvcmlvLmljcGJyYXNpbC5nb3YuYnIvbGNyL0NBSVhBL0FDQ0FJ\n" +
		"WEEvYWNjYWl4YXYyLmNybDBSBggrBgEFBQcBAQRGMEQwQgYIKwYBBQUHMAKGNmh0\n" +
		"dHA6Ly9jZXJ0aWZpY2Fkb2RpZ2l0YWwuY2FpeGEuZ292LmJyL2FpYS9hY2NhaXhh\n" +
		"LnA3YjANBgkqhkiG9w0BAQ0FAAOCAgEABkatqNTPjoVi9++1DWtG7m+sg3VeijqU\n" +
		"xAhKwDn9X9B6/G2oOOZhSPATqxhJtlBR8dj97FaUBPMiD4JmdDEQGT32891zvJtw\n" +
		"ac5zy/8atqkrh2w5xMTR7GOxnOs3mK0d2jRZ1CIoj9o8Z0r9DFXlw1CQgHWOiYhV\n" +
		"pKZhXSGUy+M6sbgSb2HZsmZlekq3wXeI53GmDOVKyZemze86uVwK5QONN1F24Ujl\n" +
		"t4uNCU3s9JSJ+cRYisHR7YuN9n89INwyDG3WxG5exDi07oP1dCWffJWbNItmcLRD\n" +
		"2huwJDGE4bhc1bbBjaM8/d3NRg5au5BYg2E9K+gZ4/0uKtsWBQllceplD4e8s1nW\n" +
		"OFUJ766wq9FSTDDMmik5L3tFvxtMXUoTrMapQ1PvXWiHXafb8O//vl2q2JrSbW2Y\n" +
		"4HfYy7C7tDHd6GWvfo8dsNv6okZO4uE9gFM/xv/QLk/kIU1F/u7t4I3jJiZ+Dgo7\n" +
		"vtwSxyoVfLYsNSOqQLnr868wOl56IKVAwdh/C7HTOSGvqO7y+xW49wAdptcIdqsU\n" +
		"YMKsXhXZAFtuaFXVGWPAtoTJkPj8Q4iE7OIo7rLxMHDwTqfQ0Vro5cwBfbF9+yY8\n" +
		"ksrhTzUwVTLjHurX9jiYRl2/h7KOqcbeZGglWBu3J5UysPwDDlRufkNGnc1AlMYB\n" +
		"zQNfoyaMgTM=\n" +
		"-----END CERTIFICATE-----";
	private static final String CERT =
		"-----BEGIN CERTIFICATE-----\n" +
		"MIIHBzCCBO+gAwIBAgIIPzAKKSpNEggwDQYJKoZIhvcNAQELBQAwXTELMAkGA1UE\n" +
		"BhMCQlIxEzARBgNVBAoMCklDUC1CcmFzaWwxIDAeBgNVBAsMF0NhaXhhIEVjb25v\n" +
		"bWljYSBGZWRlcmFsMRcwFQYDVQQDDA5BQyBDQUlYQSBQSiB2MjAeFw0xNTAzMzEx\n" +
		"MzI2NDRaFw0xNjAzMzAxMzI2NDRaMIGJMQswCQYDVQQGEwJCUjETMBEGA1UECgwK\n" +
		"SUNQLUJyYXNpbDEgMB4GA1UECwwXQ2FpeGEgRWNvbm9taWNhIEZlZGVyYWwxFzAV\n" +
		"BgNVBAsMDkFDIENBSVhBIFBKIHYyMSowKAYDVQQDDCFFTVBSRVNBIERFIFRFU1RF\n" +
		"IEdSUkY6MzAwMzAwMzAwMzAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n" +
		"AQCzMG+k/Dn32L88RT51ufsRzET1FQOqMqmdGnWnKaoAYYiXmHxK0lNU96B9/zSf\n" +
		"x8g4SSAFcK7aYDZa+dnz5InR3F65Pu+EowkBtIwR3veUZtLBZQhtVI1y2+pCuMLP\n" +
		"J8oXKaz9zvaVJdqFeTtC+MIz0AaPBZTwA7gSPP1RyairrHff5P21rwcT8mGZiPw5\n" +
		"JUgpu9e8SyEgzE/d+xXxpgDNrEb9GRp+6+qUUXu+MsL/2lO0X8yKZfPUzgMbW3hv\n" +
		"rVse1Zv6EGLTPzyA1PEWKIyjZ/49QFm0FWiY9uP1Now0+Q3sZ98d7W9clM9zmdpU\n" +
		"LjO6oi0tf0TBRgxOv3gGhkbpAgMBAAGjggKcMIICmDAOBgNVHQ8BAf8EBAMCBeAw\n" +
		"KQYDVR0lBCIwIAYIKwYBBQUHAwIGCCsGAQUFBwMEBgorBgEEAYI3FAICMB0GA1Ud\n" +
		"DgQWBBSM7K/8fVtJmAXw/cAxj4R7Gp8y8TAfBgNVHSMEGDAWgBRhPx6NgdOeBnGe\n" +
		"Kz7wxLmEyMvdYzCBnQYDVR0RBIGVMIGSoBsGBWBMAQMCoBIEEFJFU1BPTlNBVkVM\n" +
		"IEdSUkagGQYFYEwBAwOgEAQONTc2OTAyMjQwMDAxOTCgPwYFYEwBAwSgNgQ0MTEx\n" +
		"MTE5MDkzMDAzMDAzMDAzMDAwMDAwMDAwMDAwMDAwMDAwMDB3MzIzMjMySVBHSkpB\n" +
		"TaAXBgVgTAEDB6AOBAwwMDAwMDAwMDAwMDAwZwYDVR0gBGAwXjBcBgZgTAECAQkw\n" +
		"UjBQBggrBgEFBQcCARZEaHR0cHM6Ly9jZXJ0aWZpY2Fkb2RpZ2l0YWwuY2FpeGEu\n" +
		"Z292LmJyL2RvY3VtZW50b3MvZHBjYWMtY2FpeGFwai5wZGYwgbkGA1UdHwSBsTCB\n" +
		"rjAtoCugKYYnaHR0cDovL2xjci5jYWl4YS5nb3YuYnIvYWNjYWl4YXBqdjIuY3Js\n" +
		"MC6gLKAqhihodHRwOi8vbGNyMi5jYWl4YS5nb3YuYnIvYWNjYWl4YXBqdjIuY3Js\n" +
		"ME2gS6BJhkdodHRwOi8vcmVwb3NpdG9yaW8uaWNwYnJhc2lsLmdvdi5ici9sY3Iv\n" +
		"Q0FJWEEvQUNDQUlYQVBGL2FjY2FpeGFwanYyLmNybDBWBggrBgEFBQcBAQRKMEgw\n" +
		"RgYIKwYBBQUHMAKGOmh0dHA6Ly9jZXJ0aWZpY2Fkb2RpZ2l0YWwuY2FpeGEuZ292\n" +
		"LmJyL2FpYS9hY2NhaXhhcGp2Mi5wN2IwDQYJKoZIhvcNAQELBQADggIBAAiDfttk\n" +
		"HLx8qkL8SES4TAhnlZA5MS5eLnl+zkV0gnguTRsLHmjVnPkMijOHypJWP7URE1L+\n" +
		"U5sIUxvrkDO8hz7NNwjhiVYEVIieZcjrrvsyCkMIT5jYD1Po2ebtUzkOfzeGdCCb\n" +
		"ft6QgpsUPKiY/DaHQRkLVL9aMbX7anso71hGEWGMS7UdDpqzX2l8oPU+ponCZAej\n" +
		"igyFgGiP4zU/N7UV41gTnGOyb6mPTaQ9Q7sKeITqI7NOCohKq883s0jE62bxvVfs\n" +
		"N6un2DUXRlFMwOtUu1GlTU1TRLrRZjqZ+fVZljgns3TEu8hjC72+RlvD2mxvWmLr\n" +
		"6e1J+OvL5MZqSnX5HjKof5nV7hgoiOx4Y4sNnnkh9ishUk0RoHxYZ/1hfBk/764D\n" +
		"BjO0zCLjidNmFaYWZnxId+KZMCmIkS7PIVY0hLmYe+ZuYLe4qAyesSzZn/wBF+om\n" +
		"F6QmfjDfi8PkzVKkUCaG39fxLM65EdqOea/3Sv9Bp1tZjdRoIn1/WQBG8lobKRZt\n" +
		"PvrWNwedTD2jTzS8NIUEPwV+gURL4PbqXamYr0xzObeXkcNvBULSrBqxEtoo9K5i\n" +
		"GuCEmIrz28T864lBBcXcDlJU8ZDFlSmzWXoaBxD2E8JXKG6fkwft8S0IUysNkG4m\n" +
		"9iuDLlsoB6QMxBsMxsMTbxsStTg2ifVBDjmh\n" +
		"-----END CERTIFICATE-----";
	public static void main(final String[] args)
	{
		if (LOG_LEVEL < LOG_LEVEL_INFO)
		{
			class CertificateReader implements X509CertificateReader
			{
				private int i = 0;
				private final String[] list = { ROOT_CA, INTER_CA, FINAL_CA };
				@Override public boolean hasNext() { return i < list.length; }
				@Override public byte[] readNext() throws IOException { return list[i++].getBytes(); }
			}
			System.out.println("NharuCertStore basic test");
			try
			{
				System.out.print("Creating a trusted certificate store... ");
				final NharuCertStore store = new NharuCertStore(new DERX509CollectionParams(new CertificateReader(), null));
				System.out.println("Done!");
				try
				{
					final NharuX509Certificate cert = NharuX509Factory.generateCertificate(CERT.getBytes());
					System.out.print("Validating an end-user certificate... ");
					if (!store.isTrusted(cert, false)) System.err.println("Failed!");
					else System.out.println("Done!");
				}
				catch (final CertificateException e) { e.printStackTrace(); }
			}
			catch (final InvalidAlgorithmParameterException | IOException e) { e.printStackTrace(); }
		}
	}
}
