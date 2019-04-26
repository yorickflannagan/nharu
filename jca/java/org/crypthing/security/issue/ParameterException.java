package org.crypthing.security.issue;

import java.security.GeneralSecurityException;

/**
 * Raised if a certificate profile is not entirely valid.
 * @since 1.3.0
 */
public class ParameterException extends GeneralSecurityException
{
	private static final long serialVersionUID = 487912093149156883L;
	public ParameterException(String message) { super(message); }
	public ParameterException(Exception cause) { super(cause); }
	public ParameterException(String message, Exception cause) { super(message, cause); }
}