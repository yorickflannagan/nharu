package org.crypthing.security.issue;

import java.security.GeneralSecurityException;

public class CertificateProfileException extends GeneralSecurityException
{
	private static final long serialVersionUID = -8224373992393978418L;
	public CertificateProfileException(String message) { super(message); }
	public CertificateProfileException(Exception cause) { super(cause); }
	public CertificateProfileException(String message, Exception cause) { super(message, cause); }
}