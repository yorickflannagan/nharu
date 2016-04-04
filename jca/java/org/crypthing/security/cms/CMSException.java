package org.crypthing.security.cms;

import java.security.GeneralSecurityException;

/**
 * Root CMS exception
 * @author magut
 *
 */
public class CMSException extends GeneralSecurityException
{
	private static final long serialVersionUID = 629739870522484355L;
	public CMSException() {}
	public CMSException(final String s) { super(s); }
	public CMSException(final Throwable cause) { super(cause); }
	public CMSException(final String message, final Throwable cause) { super(message, cause); }
}
