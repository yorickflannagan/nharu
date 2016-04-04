package org.crypthing.security.cms;

/**
 * Thrown if could not parse (or encode) CMS document
 * @author magut
 *
 */
public class CMSParsingException extends CMSException
{
	private static final long serialVersionUID = -6540983145518911979L;
	public CMSParsingException() {}
	public CMSParsingException(final String s) { super(s); }
	public CMSParsingException(final Throwable cause) { super(cause); }
	public CMSParsingException(final String message, final Throwable cause) { super(message, cause); }
}
