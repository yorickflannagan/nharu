package org.crypthing.security.cms;

/**
 * Thrown if CMS SignedData signature does not match
 * @author magut
 *
 */
public class CMSSignatureException extends CMSException
{
	private static final long serialVersionUID = 3078760401353993634L;
	public CMSSignatureException() {}
	public CMSSignatureException(final String s) { super(s); }
	public CMSSignatureException(final Throwable cause) { super(cause); }
	public CMSSignatureException(final String message, final Throwable cause) { super(message, cause); }
}
