package org.crypthing.security.issue;

/**
 * Implements a profile to issue certificates for CAs.
 * @since 1.3.0
 */
public class CAProfile extends CertificateProfile
{
	public CAProfile()
	{
		validity = 9;
		subjectKeyIdentifier = true;
		subjectAltName = false;
		basicConstraints = true;
	}
	@Override public void check(CertificateParams params) throws CertificateProfileException {}
}