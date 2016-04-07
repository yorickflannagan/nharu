package org.crypthing.security.cert;

import org.crypthing.security.x509.NharuX509Certificate;

public interface TrustedStore
{
	/**
	 * Check if specified certificate is trusted.
	 * @param cert - the certificate to check.
	 * @return true if the certificate was signed by a trusted CA present in the CertStore.
	 */
	boolean isTrusted(NharuX509Certificate cert);
}
