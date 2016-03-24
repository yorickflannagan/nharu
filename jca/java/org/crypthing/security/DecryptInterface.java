package org.crypthing.security;

import java.security.GeneralSecurityException;

public interface DecryptInterface
{
	int plainTextLength(String padding);
	byte[] decrypt(byte[] data, String padding) throws GeneralSecurityException;
}
