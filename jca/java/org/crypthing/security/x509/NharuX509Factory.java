package org.crypthing.security.x509;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateFactorySpi;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;

import org.crypthing.util.NharuArray;
import org.crypthing.security.LogDevice;
import org.crypthing.security.cms.CMSParsingException;
import org.crypthing.security.cms.CMSSignedData;

import static org.crypthing.security.LogDevice.LOG_LEVEL;
import static org.crypthing.security.LogDevice.LOG_LEVEL_DEBUG;
import static org.crypthing.security.LogDevice.LOG_LEVEL_INFO;

/**
 * <h1>X.509 Certificate and CRL parsing impĺementation.</h1>
 * <p>Certificate cache configuration entries:</p>
 * <ul>
 * <li>org.crypthing.security.provider.NharuX509Certificate.cacheSize: size of cache. Default 500;</li>
 * <li>org.crypthing.security.provider.NharuX509Certificate.cleanerTimeout: sleep time between to cache clean-up. Default 60000</li>
 * <li>org.crypthing.security.provider.NharuX509Certificate.cacheMinSize: minimum size of cache. Default: 400</li>
 * </ul>
 * <p>
 * Limitations:<b>
 * This version only supports certificates and CRL's signed with RSA algorithms. 
 * </p>
 * @author yorick.flannagan@gmail.com & diego.sohsten@globo.com
 *
 */
public final class NharuX509Factory extends CertificateFactorySpi
{
	private static final String DBG_CACHE_PARAMS = "Certificate cache initialized with following parameters: ";
	private static final LogDevice LOG = new LogDevice(NharuX509Factory.class.getName());
	private static final CertificateFactory backup;
	static
	{
			try {
				backup = CertificateFactory.getInstance("X.509", "SUN");
			} catch (CertificateException | NoSuchProviderException e) {
				throw new RuntimeException(e);
			}
	}

	/*
	 * Certificate cache
	 * This must be implementended due to Java SSL implementation
	 */
	private static final String CACHE_SIZE_ENTRY = "org.crypthing.security.provider.NharuX509Certificate.cacheSize";
	private static final int DEFAULT_CACHE_SIZE = 500;
	private static final int CACHE_SIZE;
	private static final String CLEANER_TIMEOUT_ENTRY = "org.crypthing.security.provider.NharuX509Certificate.cleanerTimeout";
	private static final int DEFAULT_CLEANER_TIMEOUT = 60000;
	private static final long CLEANER_TIMEOUT;
	private static final String CACHE_MIN_SIZE_ENTRY = "org.crypthing.security.provider.NharuX509Certificate.cacheMinSize";
	private static final int DEFAULT_CACHE_MIN_SIZE = 400;
	private static final int CACHE_MIN_SIZE;
	private static final ConcurrentHashMap<NharuArray, NharuX509Certificate> transientCache;
	private static final ConcurrentHashMap<NharuArray, NharuX509Certificate> longTermCache;
	private static boolean isRunning;
	static
	{
		CACHE_SIZE = Integer.getInteger(CACHE_SIZE_ENTRY, DEFAULT_CACHE_SIZE);
		CLEANER_TIMEOUT = Long.getLong(CLEANER_TIMEOUT_ENTRY, DEFAULT_CLEANER_TIMEOUT);
		CACHE_MIN_SIZE = Integer.getInteger(CACHE_MIN_SIZE_ENTRY, DEFAULT_CACHE_MIN_SIZE);
		transientCache = new ConcurrentHashMap<>((int) (CACHE_SIZE * 1.10));
		longTermCache  = new ConcurrentHashMap<>();
		if (LOG_LEVEL < LOG_LEVEL_INFO)
		{
			final StringBuilder builder = new StringBuilder();
			builder.append(DBG_CACHE_PARAMS);
			builder.append("CACHE_SIZE = ");
			builder.append(CACHE_SIZE);
			builder.append(", CLEANER_TIMEOUT = ");
			builder.append(CLEANER_TIMEOUT);
			builder.append(" and CACHE_MIN_SIZE = ");
			builder.append(CACHE_MIN_SIZE);
			LOG.debug(builder.toString());
		}
	}
	static void cacheGiveBack(final NharuX509Certificate cert) { cachePut(new NharuArray(cert.getOriginalEncoding()), cert);}
	public static void cachePromote(final NharuX509Certificate cert)
	{
		final NharuArray key = new NharuArray(cert.getOriginalEncoding());
		if (transientCache.get(key) != null) transientCache.remove(key);
		longTermCache.put(key, cert);
	}
	static synchronized void blackHawkIsDown() { isRunning = false; }
	private static void cachePut(final NharuArray key, final NharuX509Certificate entry)
	{
		final NharuX509Certificate old = transientCache.put(key, entry);
		if (old != null) old.closeHandle();
	}
	private static synchronized void hireServant()
	{
		final CacheCleaner cleaner = new CacheCleaner(transientCache, CACHE_SIZE, CACHE_MIN_SIZE, CLEANER_TIMEOUT);
		Runtime.getRuntime().addShutdownHook( new CleanerShutDown(cleaner));
		cleaner.start();
		isRunning = true;
	}


	public NharuX509Factory() { if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack(); }

	@Override
	public CRL engineGenerateCRL(final InputStream inStream) throws CRLException
	{
		if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack();
		if (inStream == null) throw new NullPointerException();
		NharuX509CRL crl = null;
		try { crl = generateCRL(readAllStream(inStream)); }
		catch (final IOException e) { throw new CRLException(e); }
		return crl;
	}
	public static NharuX509CRL generateCRL(final byte[] buffer) throws CRLException
	{
		if (buffer.length == 0) throw new CRLException("Empty stream");
		return new NharuX509CRL(buffer);
	}

	@SuppressWarnings("restriction")
	@Override
	public Collection<? extends CRL> engineGenerateCRLs(final InputStream inStream) throws CRLException
	{
		if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack();
		// TODO: Must implement engineGenerateCRLs
		// inStream is a PKCS #7 or (holly shit!) "a sequence of DER encoded X.509 CRLs (in binary or base 64 encoded format)"
		final Collection<? extends CRL> col = (new sun.security.provider.X509Factory()).engineGenerateCRLs(inStream);
		final Iterator<? extends CRL> it = col.iterator();
		final ArrayList<NharuX509CRL> result = new ArrayList<>();
		while (it.hasNext())
		{
			final CRL entry = it.next();
			if (!(entry instanceof X509CRL)) return col;
			result.add(generateCRL(((X509CRL) entry).getEncoded()));
		}
		return result;
	}

	@Override
	public Certificate engineGenerateCertificate(final InputStream inStream) throws CertificateException
	{
		if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack();
		if (inStream == null)
		{
			if (LOG_LEVEL < LOG_LEVEL_INFO)
			{
				longTermCache.clear();
				transientCache.clear();
			}
			throw new NullPointerException("Missing input stream");
		}
		Certificate cert = null;
		byte[] buffer=null;
		try { buffer = readAllStream(inStream); cert = generateCertificate(buffer); }
		catch (NharuX509CertificateException e)
		{
			if(e.getReason() == NharuX509CertificateException.NH_UNSUPPORTED_MECH_ERROR)
			{
				cert = backup.generateCertificate(new ByteArrayInputStream(buffer));
			}
		}
		catch (IOException e) { throw new CertificateException(e); }
		return cert;
	}

	public static NharuX509Certificate generateCertificate(final byte[] buffer) throws CertificateException
	{
		if (buffer == null || buffer.length == 0) throw new CertificateException("Empty stream");
		final NharuArray key = new NharuArray(buffer);
		NharuX509Certificate cert = longTermCache.get(key);
		if (cert == null) cert = transientCache.get(key);
		if (cert == null)
		{
			cert = new NharuX509Certificate(buffer);
			cachePut(key, cert);
			if (!isRunning) hireServant();
		}
		return cert;
	}

	@SuppressWarnings("restriction")
	@Override
	public Collection<? extends Certificate> engineGenerateCertificates(InputStream inStream) throws CertificateException
	{
		if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack();
		final ArrayList<NharuX509Certificate> result = new ArrayList<>();
		try
		{
			final CMSSignedData cms = new CMSSignedData(readAllStream(inStream));
			final X509Certificate[] certs = cms.getCertificates();
			if (certs != null) for (int i = 0; i < certs.length; i++) result.add((NharuX509Certificate) certs[i]);
		}
		catch (final CMSParsingException | IOException swallowed)
		{
			// inStream is a PKCS #7 or (holly shit!) "a sequence of DER encoded X.509 certificates (in binary or base 64 encoded format)"
			final Collection<? extends Certificate> col = (new sun.security.provider.X509Factory()).engineGenerateCertificates(inStream);
			final Iterator<? extends Certificate> it = col.iterator();
			while (it.hasNext())
			{
				final Certificate entry = it.next();
				if (!(entry instanceof X509Certificate)) return col;
				result.add(generateCertificate(entry.getEncoded()));
				
			}
		}
		return result;
	}

	@Override
	public CertPath engineGenerateCertPath(InputStream inStream) throws CertificateException
	{
		// TODO: Must implement engineGenerateCertPath(InputStream)
		// See sun.security.provider.certpath.X509CertPath and NharuCertPath
		if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack();
		throw new UnsupportedOperationException();
	}

	@Override
	public CertPath engineGenerateCertPath(InputStream inStream, String encoding) throws CertificateException
	{
		// TODO: Must implement engineGenerateCertPath(InputStream, String)
		// See sun.security.provider.certpath.X509CertPath
		if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack();
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<String> engineGetCertPathEncodings()
	{
		// TODO: Must implement engineGetCertPathEncodings
		// See CertPath
		if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack();
		throw new UnsupportedOperationException();
	}


	private static final int BUFF_LEN = 4096;
	private byte[] readAllStream(final InputStream is) throws IOException
	{
		final byte[] buffer;
		final int len = is.available();
		if (len > 0)
		{
			buffer = new byte[len];
			is.read(buffer);
		}
		else
		{
			final ByteArrayOutputStream out = new ByteArrayOutputStream(BUFF_LEN);
			byte[] buf = new byte[BUFF_LEN];
			int i;
			while ((i = is.read(buf)) != -1) out.write(buf, 0, i);
			buffer = out.toByteArray();
		}
		return buffer;
	}
}
