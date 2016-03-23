package org.crypthing.security.cert;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.security.x509.NharuX509Factory;
import org.crypthing.security.LogDevice;

import static org.crypthing.security.LogDevice.LOG_LEVEL;
import static org.crypthing.security.LogDevice.LOG_LEVEL_TRACE;
import static org.crypthing.security.LogDevice.LOG_LEVEL_FATAL;

public final class X509CertCollectionParams implements CertStoreParameters
{
	private static final String MSG_TRACE = "X509CertCollectionParams has received following certificates:\n";
	private static final String ERROR_ENCODING = "Error while decoding certificate";
	private static final LogDevice LOG = new LogDevice(X509CertCollectionParams.class.getName());

	private final ArrayList<NharuX509Certificate> certs;

	public X509CertCollectionParams(final KeyStore ks) throws KeyStoreException
	{
		if (LOG_LEVEL <= LOG_LEVEL_TRACE)
		{
			final StringBuilder builder = new StringBuilder();
			builder.append(MSG_TRACE);
			final Enumeration<String> aliases = ks.aliases();
			while (aliases.hasMoreElements())
			{
				final String alias = aliases.nextElement();
				if (ks.isCertificateEntry(alias) && ks.getCertificate(alias) instanceof X509Certificate ) builder.append(((X509Certificate) ks.getCertificate(alias)).getSubjectX500Principal().getName());
				else if (ks.isKeyEntry(alias))
				{
					Certificate[] chain = ks.getCertificateChain(alias);
					if (chain != null && chain.length > 0 && chain[0] instanceof X509Certificate ) builder.append(((X509Certificate) chain[0]).getSubjectX500Principal().getName());
				}
			}
			LOG.trace(builder.toString());
		}
		certs = new ArrayList<>(ks.size());
            for (Enumeration<String> e = ks.aliases(); e.hasMoreElements(); )
            {
                  String alias = e.nextElement();
                  Certificate cert = null;
                  if (ks.isCertificateEntry(alias)) cert = ks.getCertificate(alias);
                  else if (ks.isKeyEntry(alias))
                  {
				Certificate[] chain = ks.getCertificateChain(alias);
				if ((chain != null) && (chain.length > 0)) cert = chain[0];
                  }
                  if (cert != null)
                  {
      			if (cert instanceof NharuX509Certificate) certs.add((NharuX509Certificate) cert);
				else
				{
					try { certs.add(NharuX509Factory.generateCertificate(cert.getEncoded()));}
					catch (CertificateException ex)
					{
						if (LOG_LEVEL < LOG_LEVEL_FATAL) LOG.error(ERROR_ENCODING, ex);
						throw new KeyStoreException(ex);
					}
				}
                  }
             }
	}

	public Iterator<NharuX509Certificate> iterator() { return certs.iterator(); }
	public Collection<NharuX509Certificate> entries() { return certs; }

	@Override
	public Object clone()
	{
		try { return super.clone(); }
		catch (final CloneNotSupportedException e) { /* Cannot happen */ throw new InternalError(e.toString()); }
	}
}
