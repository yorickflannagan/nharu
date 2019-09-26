package org.crypthing.security.issue;

/**
 * Implements a profile to certificate issuing
 * @since 1.3.0
 */
public abstract class CertificateProfile
{
	int version = 2;
	String signatureAlgorithm = "SHA256withRSA";
	int validity = 3;
	String publicKeyAlgorithm = "RSA";
	boolean issuerUniqueID = false;
	boolean subjectUniqueID = false;
	boolean authorityKeyIdentifier = true;
	boolean subjectKeyIdentifier = false;
	boolean keyUsage = true;
	boolean certificatePolicies = false;
	boolean policyMappings = false;
	boolean subjectAltName = true;
	boolean issuerAltName = false;
	boolean subjectDirectoryAttributes = false;
	boolean basicConstraints = false;
	boolean nameConstraints = false;
	boolean policyConstraints = false;
	boolean extKeyUsage = false;
	boolean cRLDistributionPoints = true;
	boolean inhibitAnyPolicy = false;
	boolean freshestCRL = false;
	boolean authorityInfoAccess = false;
	boolean subjectInfoAccess = false;
	protected CertificateProfile() {}
	public abstract void check(CertificateParams params) throws CertificateProfileException;
}