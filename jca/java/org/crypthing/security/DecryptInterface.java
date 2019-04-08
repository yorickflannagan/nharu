package org.crypthing.security;

import java.security.GeneralSecurityException;

/**
 * RSA Private decryption implementation callback. 
 * @author magut
 *
 */
public interface DecryptInterface
{
	/**
	 * Returns the size in bytes of deciphered text
	 * @param padding: RSA padding algorithm.
	 * @return the size.
	 */
	int plainTextLength(String padding);

	/**
	 * Private decrypts specified contents.
	 * @param data: data to be deciphered.
	 * @param padding: RSA padding algorithm
	 * @return deciphered text
	 * @throws GeneralSecurityException on failure
	 */
	byte[] decrypt(byte[] data, String padding) throws GeneralSecurityException;
}
