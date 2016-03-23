package org.crypthing.security.cert;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.security.x509.NharuX509Name;

final class TrustedCertStore extends HashMap<NharuX509Name, NharuX509Certificate>
{
	private static final long serialVersionUID = 6800223905793431479L;
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws IOException { throw new NotSerializableException(); }
	TrustedCertStore() { super(128); }
	TrustedCertStore(final int initialCapacity) { super(initialCapacity); }
	TrustedCertStore(final Map<? extends NharuX509Name, ? extends NharuX509Certificate> m) { super(m); }
	TrustedCertStore(final int initialCapacity, final float loadFactor) { super(initialCapacity, loadFactor); }

	synchronized void checkChains() throws CertStoreException
	{
		if (this.size() == 0) throw new CertStoreException("CertStore must NOT be empty");
		final Iterator<NharuX509Certificate> it = values().iterator();
		while (it.hasNext())
		{
			final NharuX509Certificate subject = it.next();
			final NharuX509Certificate issuer = get(subject.getIssuer());
			if (issuer == null) throw new CertStoreException("Incomplete certificate chain for " + subject.getSubjectX500Principal().getName());
			try
			{
				subject.checkValidity();
				subject.verify(issuer.getPublicKey());
			}
			catch (final InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e)
			{
				throw new CertStoreException("Certificate issued to " + subject.getSubjectX500Principal().getName() + " is not trusted", e);
			}
		}
	}
}
