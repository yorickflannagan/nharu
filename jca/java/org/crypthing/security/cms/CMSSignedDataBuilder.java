package org.crypthing.security.cms;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.security.GeneralSecurityException;

import org.crypthing.security.SignerInterface;
import org.crypthing.security.provider.NharuProvider;
import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.util.NharuCommon;

/**
 * CMS SignedData document builder
 * @author magut
 *
 */
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

	/**
	 * Creates a new builder for this eContent.
	 * @param eContent: EncapsulatedContentInfo eContent field.
	 * @param attach: true if eContent must be attached; otherwise, false.
	 * @throws CMSParsingException
	 */
	public CMSSignedDataBuilder(final byte[] eContent, final boolean attach) throws CMSParsingException
	{
		if (eContent == null) throw new NullPointerException("Encapsulated Content argument must not be null");
		hHandle = nhcmsNewSignedDataBuilder(eContent, attach);
	}

	/**
	 * Adds specified certificate to this document.
	 * @param cert: the certificate to be embbeded.
	 * @throws CMSParsingException
	 */
	public void addCertificate(final NharuX509Certificate cert) throws CMSParsingException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (cert == null) throw new NullPointerException("Argument must not be null");
		nhcmsAddCert(hHandle, cert.getCertificateHandle());
	}

	/**
	 * Adds specified certificate chain to this document.
	 * @param certs: the chain to be embbeded.
	 * @throws CMSParsingException
	 */
	public void addCertificates(final NharuX509Certificate[] certs) throws CMSParsingException
	{
		if (certs == null) throw new NullPointerException("Argument must not be null");
		for (int i = 0; i < certs.length; i++) addCertificate(certs[i]);
	}

	/**
	 * Signs this document.
	 * @param algorithm: signing algorithm. Only SHA1withRSA, SHA256withRSA, SHA384withRSA, SHA512withRSA and MD5withRSA are supported.
	 * @param signerCert: signinf certificate.
	 * @param signer: SignerInterface implementation to sign this document.
	 * @throws GeneralSecurityException
	 */
	public void sign(final String algorithm, final NharuX509Certificate signerCert, final SignerInterface signer) throws GeneralSecurityException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (algorithm == null || algorithm.length() == 0 || signer == null) throw new NullPointerException("Arguments must not be null");
		nhcmsSign(hHandle, signerCert.getCertificateHandle(), NharuCommon.getAlgorithmConstant(algorithm), signer);
	}

	/**
	 * Encodes CMS document.
	 * @return DER encoded CMS SignedData document.
	 * @throws CMSParsingException
	 */
	public byte[] encode() throws CMSParsingException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		return nhcmsEncode(hHandle);
	}

	/**
	 * Releases native handler. Must be called once when object is no longer needed.
	 */
	public void releaseBuilder()
	{
		if (hHandle != 0)
		{
			nhcmsReleaseSignedDataBuilder(hHandle);
			hHandle = 0;
		}
	}
}
