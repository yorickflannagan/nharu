package org.crypthing.security.x509;

import java.security.cert.CertificateException;

public class NharuX509CertificateException extends CertificateException 
{
	/* Expand as the exception must me handled */
	public static final int NH_UNSUPPORTED_MECH_ERROR = 1059;
	
	private static final long serialVersionUID = -6624367345399264911L;
	private final int rv;
	public NharuX509CertificateException(String msg, int rv)
	{
		super(msg);
		this.rv=rv;
	}
	
	public int getReason() {
		return rv;
	}

}
