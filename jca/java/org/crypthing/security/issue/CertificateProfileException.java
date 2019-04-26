package org.crypthing.security.issue;

import java.security.GeneralSecurityException;

/**
 * Raised if a certificate profile is not entirely valid.
 * @since 1.3.0
 */
public class CertificateProfileException extends GeneralSecurityException
{
	private static final long serialVersionUID = -8224373992393978418L;
	public CertificateProfileException(String message) { super(message); }
	public CertificateProfileException(Exception cause) { super(cause); }
	public CertificateProfileException(String message, Exception cause) { super(message, cause); }
}