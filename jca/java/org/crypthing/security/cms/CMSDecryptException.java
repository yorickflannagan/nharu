package org.crypthing.security.cms;

/**
 * Thrown if could not decrypt a CMS EnvedelopedData document
 * @author magut
 *
 */
public class CMSDecryptException extends CMSException
{
	private static final long serialVersionUID = 1442326344262606694L;
	public CMSDecryptException() {}
	public CMSDecryptException(final String s) { super(s); }
	public CMSDecryptException(final Throwable cause) { super(cause); }
	public CMSDecryptException(final String message, final Throwable cause){ super(message, cause); }
}
