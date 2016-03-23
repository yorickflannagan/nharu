package org.crypthing.security.cms;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.security.GeneralSecurityException;

import org.crypthing.security.provider.NharuProvider;
import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.util.NharuCommon;

public final class CMSSignedDataBuilder
{
	static { NharuProvider.isLoaded(); }
	private long hHandle;
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws NotSerializableException { throw new NotSerializableException(); }
	private void readObjectNoData() throws ObjectStreamException { throw new NotSerializableException(); }

	private static native long nhcmsNewSignedDataBuilder(byte[] eContent, boolean attach) throws CMSParsingException;
	private static native void nhcmsReleaseSignedDataBuilder(long handle);
	private static native void nhcmsAddCert(long cmsHandle, long certHandle)  throws CMSParsingException;
	private static native void nhcmsSign(long cmsHandle, long certHandle, int mechanism, SignerInterface signer) throws GeneralSecurityException;
	private static native byte[] nhcmsEncode(long handle) throws CMSParsingException;

	public CMSSignedDataBuilder(final byte[] eContent, final boolean attach) throws CMSParsingException
	{
		if (eContent == null) throw new NullPointerException("Encapsulated Content argument must not be null");
		hHandle = nhcmsNewSignedDataBuilder(eContent, attach);
	}

	public void addCertificate(final NharuX509Certificate cert) throws CMSParsingException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (cert == null) throw new NullPointerException("Argument must not be null");
		nhcmsAddCert(hHandle, cert.getCertificateHandle());
	}

	public void addCertificates(final NharuX509Certificate[] certs) throws CMSParsingException
	{
		if (certs == null) throw new NullPointerException("Argument must not be null");
		for (int i = 0; i < certs.length; i++) addCertificate(certs[i]);
	}

	public void sign(final String algorithm, final NharuX509Certificate signerCert, final SignerInterface signer) throws GeneralSecurityException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (algorithm == null || algorithm.length() == 0 || signer == null) throw new NullPointerException("Arguments must not be null");
		nhcmsSign(hHandle, signerCert.getCertificateHandle(), NharuCommon.getAlgorithmConstant(algorithm), signer);
	}

	public byte[] encode() throws CMSParsingException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		return nhcmsEncode(hHandle);
	}

	public void releaseBuilder()
	{
		if (hHandle != 0)
		{
			nhcmsReleaseSignedDataBuilder(hHandle);
			hHandle = 0;
		}
	}
}
