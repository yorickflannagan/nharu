package org.crypthing.security.x509;

import java.security.cert.CertificateRevokedException;
import java.security.cert.X509Certificate;

public interface CRLChecker
{
	void validate(X509Certificate cert) throws CertificateRevokedException;
}
