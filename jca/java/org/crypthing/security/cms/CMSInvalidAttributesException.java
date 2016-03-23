package org.crypthing.security.cms;

public class CMSInvalidAttributesException extends CMSException
{
	private static final long serialVersionUID = 4731052663318890307L;
	public CMSInvalidAttributesException() {}
	public CMSInvalidAttributesException(final String s) { super(s); }
	public CMSInvalidAttributesException(final Throwable cause) { super(cause); }
	public CMSInvalidAttributesException(final String message, final Throwable cause) { super(message, cause); }
}
