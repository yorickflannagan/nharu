package org.crypthing.security;

import java.security.GeneralSecurityException;

/**
 * RSA signing implementation callback
 * @author magut
 *
 */
public interface SignerInterface
{
	/**
	 * Return the size in bytes of the signature
	 * @param algorithm: signing algorithm.
	 * @return the size.
	 */
	int signatureLength(String algorithm);

	/**
	 * Signs specified contents.
	 * @param data: contents to be signed.
	 * @param algorithm: signing algorithm.
	 * @return the signature
	 * @throws GeneralSecurityException
	 */
	byte[] sign(byte[] data, String algorithm) throws GeneralSecurityException;
}
