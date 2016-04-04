package org.crypthing.security.cms;

/**
 * Thrown if a given certificate is not trusted.
 * @author magut
 *
 */
public class UntrustedCertificateException extends CMSException
{
	private static final long serialVersionUID = -5897490058255066427L;
	public UntrustedCertificateException() {}
	public UntrustedCertificateException(final String s) { super(s); }
	public UntrustedCertificateException(final Throwable cause) { super(cause); }
	public UntrustedCertificateException(final String message, final Throwable cause) { super(message, cause); }
}
