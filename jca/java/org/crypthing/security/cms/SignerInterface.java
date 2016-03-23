package org.crypthing.security.cms;

import java.security.GeneralSecurityException;

public interface SignerInterface
{
	int signatureLength(String algorithm);
	byte[] sign(byte[] data, String algorithm) throws GeneralSecurityException;
}
