package org.crypthing.security.auth;

import java.security.Principal;
import java.security.cert.CertificateException;

import org.crypthing.security.crlservice.CertStatus;
import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.security.x509.NharuPKIBRParser;


@SuppressWarnings("restriction")
public final class X509Identity implements Principal
{
	private final transient NharuX509Certificate credentials;
	private transient NharuPKIBRParser parser = null;
	private final transient CertStatus status;
	
	public X509Identity(final NharuX509Certificate credentials, final CertStatus status)
	{
		this.credentials = credentials;
		this.status = status;
	}

	@Override
	public String getName()
	{
		return credentials.getSubjectX500Principal().getName();
	}

	public NharuPKIBRParser getParser() throws CertificateException
	{
		if (parser == null) parser = NharuPKIBRParser.parse(credentials);
		return parser;
	}

	public CertStatus getStatus()
	{
		return status;
	}

	public NharuX509Certificate getCredentials()
	{
		return credentials;
	}
}
