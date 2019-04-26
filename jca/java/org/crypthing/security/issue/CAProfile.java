package org.crypthing.security.issue;

/**
 * Implements a profile to issue certificates for CAs.
 * @since 1.3.0
 */
public final class CAProfile extends CertificateProfile
{
	public CAProfile()
	{
		super();
		validity = 9;
		subjectKeyIdentifier = true;
		subjectAltName = false;
		basicConstraints = true;
	}
}