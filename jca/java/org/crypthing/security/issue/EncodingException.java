package org.crypthing.security.issue;

import java.security.GeneralSecurityException;

/**
 * Thrown if an invalid encoding is found in a document
 */
public class EncodingException extends GeneralSecurityException
{
	private static final long serialVersionUID = 6843488935275999517L;
	public EncodingException() { super(); }
	public EncodingException(String message) { super(message); }
	public EncodingException(String message, Throwable cause) { super(message, cause); }
	public EncodingException(Throwable cause) { super(cause); }
}