package org.crypthing.security.cms;

/**
 * Thrown if an unsupported CMS document type is given for parsing.
 * @author magut
 *
 */
public class UnsupportedCMSTypeException extends CMSException
{
	private static final long serialVersionUID = -590800782721596873L;
	public UnsupportedCMSTypeException() { }
	public UnsupportedCMSTypeException(final String s) { super(s); }
	public UnsupportedCMSTypeException(final Throwable cause) { super(cause); }
	public UnsupportedCMSTypeException(final String message, final Throwable cause) { super(message, cause); }
}
