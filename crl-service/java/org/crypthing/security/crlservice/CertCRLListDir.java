package org.crypthing.security.crlservice;

import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.util.ArrayList;

import org.crypthing.security.x509.NharuX509CRL;
import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.security.x509.NharuX509Factory;

public class CertCRLListDir extends CRLUpdater
{
	private static final String CERT_DIR_ENTRY = "org.crypthing.security.crlservice.CertCRLListDir.certs";
	private static final String CRL_DIR_ENTRY = "org.crypthing.security.crlservice.CertCRLListDir.crls";
	private final File _certs, _crls;
	public CertCRLListDir()
	{
		String entry = System.getProperty(CERT_DIR_ENTRY);
		if (entry == null) throw new RuntimeException(CERT_DIR_ENTRY + " not found in environment");
		_certs = new File(entry);
		if (!_certs.exists() || !_certs.isDirectory()) throw new RuntimeException(CERT_DIR_ENTRY + " value is not a valid directory");
		entry = System.getProperty(CRL_DIR_ENTRY);
		_crls = new File(entry);
		if (!_crls.exists() || !_crls.isDirectory()) throw new RuntimeException(CRL_DIR_ENTRY + " value is not a valid directory");
	}
	@Override
	public long update() throws Exception
	{
		final File[] fCerts = _certs.listFiles(new FileFilter() { @Override public boolean accept(final File pathname) { return !pathname.isDirectory(); } });
		final ArrayList<NharuX509Certificate> certs = new ArrayList<>(fCerts.length);
		for (final File fCert : fCerts)
		{
			try { certs.add(NharuX509Factory.generateCertificate(readFile(fCert))); }
			catch (final CertificateException e) { /* */ }
		}
		final File[] fCrls =   _crls.listFiles(new FileFilter() { @Override public boolean accept(final File pathname) { return !pathname.isDirectory(); } });
		final ArrayList<NharuX509CRL> crls = new ArrayList<>(fCrls.length);
		for (final File fCrl : fCrls)
		{
			try { crls.add(NharuX509Factory.generateCRL(readFile(fCrl))); }
			catch (final CRLException e) { /* */ }
		}
		CRLValidator.update(certs.toArray(new NharuX509Certificate[certs.size()]), crls.toArray(new NharuX509CRL[crls.size()]));
		final long next = CRLValidator.getNextUpdate() - System.currentTimeMillis();
		return next > MIN_WAIT_TIME * 2 ? next : MIN_WAIT_TIME * 2;
	}
	private byte[] readFile(final File fCert) throws IOException
	{
		final FileInputStream in = new FileInputStream(fCert);
		try
		{
			final byte[] buffer = new byte[(int) fCert.length()];
			in.read(buffer);
			return buffer;
		}
		finally { in.close(); }
	}
}
