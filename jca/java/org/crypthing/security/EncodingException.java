package org.crypthing.security;

import java.security.GeneralSecurityException;

/**
 * Thrown if an invalid encoding is found in a document
 * @since 1.3.0
 */
public class EncodingException extends GeneralSecurityException
{
	private static final long serialVersionUID = 6843488935275999517L;
	public EncodingException() { super(); }
	public EncodingException(String message) { super(message); }
	public EncodingException(String message, Throwable cause) { super(message, cause); }
	public EncodingException(Throwable cause) { super(cause); }
}