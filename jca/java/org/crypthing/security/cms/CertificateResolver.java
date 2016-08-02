package org.crypthing.security.cms;

import java.security.cert.X509Certificate;

/**
 * Gets the certificate associated to a CMS SignerIdentifier
 * @author magut
 *
 */
public interface CertificateResolver
{
	/**
	 * Gets correspondent certificate
	 * @param signer: CMS SignerIdentifier.
	 * @return certificate or null, if signer certificate is unavailable.
	 */
	X509Certificate getCertificate(SignerIdentifier signer);
}
