package org.crypthing.security;

import java.security.GeneralSecurityException;

public interface SignerInterface
{
	int signatureLength(String algorithm);
	byte[] sign(byte[] data, String algorithm) throws GeneralSecurityException;
}
