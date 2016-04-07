package org.crypthing.security.crlservice;

import org.crypthing.security.cert.TrustedStore;
import org.crypthing.security.x509.NharuX509Certificate;

public class CertificateValidator implements TrustedStore
{
	@Override public boolean isTrusted(NharuX509Certificate cert) { return CRLValidator.checkAll(cert) == CertStatus.VALID ? true : false; }
}
