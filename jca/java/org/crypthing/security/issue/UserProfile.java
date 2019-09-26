package org.crypthing.security.issue;

/**
 * Implements a profile to issue certificates for end users.
 * @since 1.3.0
 */
public class UserProfile extends CertificateProfile
{
	@Override public void check(CertificateParams params) throws CertificateProfileException {}
}
