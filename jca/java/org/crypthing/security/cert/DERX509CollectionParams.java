package org.crypthing.security.cert;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import org.crypthing.security.LogDevice;
import static org.crypthing.security.LogDevice.LOG_LEVEL;
import static org.crypthing.security.LogDevice.LOG_LEVEL_TRACE;
import static org.crypthing.security.LogDevice.LOG_LEVEL_FATAL;


/**
 * Implements a group of NharuCertStore creation parameters.
 * @author magut
 *
 */
public final class DERX509CollectionParams implements CertStoreParameters
{
	private static final String MSG_TRACE = "DERX509CollectionParams has received following certificates:\n";
	private static final String ERROR_ENCODING = "Error while decoding certificate";
	private static final LogDevice LOG = new LogDevice(DERX509CollectionParams.class.getName());

	private final List<byte[]> certs = new ArrayList<>(128);
	private final List<byte[]> crls = new ArrayList<>(128);

	/*
	 * Only for certificates CertStore
	 */
	public DERX509CollectionParams(final KeyStore ks) throws KeyStoreException
	{
		if (LOG_LEVEL <= LOG_LEVEL_TRACE)
		{
			final StringBuilder builder = new StringBuilder();
			builder.append(MSG_TRACE);
			final Enumeration<String> aliases = ks.aliases();
			while (aliases.hasMoreElements())
			{
				final String alias = aliases.nextElement();
				if (ks.isCertificateEntry(alias) && ks.getCertificate(alias) instanceof X509Certificate)
					builder.append(((X509Certificate) ks.getCertificate(alias)).getSubjectX500Principal().getName());
				else if (ks.isKeyEntry(alias))
				{
					Certificate[] chain = ks.getCertificateChain(alias);
					if (chain != null && chain.length > 0 && chain[0] instanceof X509Certificate )
						builder.append(((X509Certificate) chain[0]).getSubjectX500Principal().getName());
				}
			}
			LOG.trace(builder.toString());
		}
		final Enumeration<String> aliases = ks.aliases();
		while (aliases.hasMoreElements())
		{
			final String alias = aliases.nextElement();
			try
			{
				if (ks.isCertificateEntry(alias)) certs.add(ks.getCertificate(alias).getEncoded());
				else if (ks.isKeyEntry(alias))
				{
					Certificate[] chain = ks.getCertificateChain(alias);
					if (chain != null && chain.length > 0) certs.add(chain[0].getEncoded());
				}
			}
			catch (final CertificateEncodingException e)
			{
				if (LOG_LEVEL < LOG_LEVEL_FATAL) LOG.error(ERROR_ENCODING, e);
				throw new KeyStoreException(e);
			}
		}
	}

	public DERX509CollectionParams(final X509CertificateReader certReader, final X509CRLReader crlReader) throws IOException
	{
		if (certReader != null) while (certReader.hasNext()) certs.add(certReader.readNext());
		if (crlReader != null) while (crlReader.hasNext()) crls.add(crlReader.readNext());
	}

	@Override
	public Object clone()
	{
		try { return super.clone(); }
		catch (final CloneNotSupportedException e) { /* Cannot happen */ throw new InternalError(e.toString()); }
	}

	Iterator<byte[]> getCertificates() { return certs.iterator(); }
	Iterator<byte[]> getCRLs() { return crls.iterator(); }
}
