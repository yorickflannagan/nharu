package org.crypthing.security.cms;

/**
 * Thrown if could not encrypt CMS EnvelopedData contents
 * @author magut
 *
 */
public class CMSEncryptException extends CMSException
{
	private static final long serialVersionUID = -8296886562270935797L;
	public CMSEncryptException() {}
	public CMSEncryptException(final String s) { super(s); }
	public CMSEncryptException(final Throwable cause) { super(cause); }
	public CMSEncryptException(final String message, final Throwable cause) { super(message, cause); }
}
