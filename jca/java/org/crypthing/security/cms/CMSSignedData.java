package org.crypthing.security.cms;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.crypthing.security.NharuRSAPublicKey;
import org.crypthing.security.cert.TrustedStore;
import org.crypthing.security.provider.NharuProvider;
import org.crypthing.security.x509.NativeParent;
import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.security.x509.NharuX509Factory;

/**
 * Parses a CMS SignedData document
 * @author magut
 *
 */
public final class CMSSignedData implements NativeParent
{
	static { NharuProvider.isLoaded(); }
	private long hHandle;
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws NotSerializableException { throw new NotSerializableException(); }
	private void readObjectNoData() throws ObjectStreamException { throw new NotSerializableException(); }

	private static native long nhcmsParseSignedData(byte[] encoding) throws CMSParsingException;
	private static native void nhcmsReleaseHandle(long handle);
	private static native byte[] nhcmsGetContent(long handle);
	private static native long[] nhcmsGetCertificates(long handle);
	private static native void nhcmsVerify(long cmsHandle, int idx, long keyHandle) throws CMSSignatureException;
	private static native void nhcmsValidate(long handle, byte[] eContent) throws CMSInvalidAttributesException;
	private static native void nhcmsValidateAttached(long handle) throws CMSInvalidAttributesException;
	private static native int nhcmsCountSigners(long handle);
	private static native long nhcmsGetSignerCertificate(long handle, int idx);
	private static native long nhcmsGetIssuerNode(long handle);
	private native SignerIdentifier nhcmsGetSignerIdentifier(long handle, int idx) throws CMSParsingException;
	private static native boolean nhcmsHasCertificates(long handle);

	private byte[] content;
	private int signers;
	/**
	 * Creates a new instance from this encoding.
	 * @param encoding: CMS SignedData DER or PEM encoding
	 * @throws CMSParsingException
	 */
	public CMSSignedData(final byte[] encoding) throws CMSParsingException
	{
		if (encoding == null) throw new NullPointerException("Encoding argument must not be null");
		hHandle = nhcmsParseSignedData(encoding);
	}

	/**
	 * Gets EncapsulatedContentInfo eContent field, if any.
	 * @return: the encapsulated content or null if it is not present.
	 */
	public byte[] getContent()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (content == null) content = nhcmsGetContent(hHandle);
		return content;
	}

	/**
	 * Gets CertificateSet field, if any.
	 * @return embedded certificates or null, if they are not present.
	 */
	public X509Certificate[] getCertificates()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		final long[] handles = nhcmsGetCertificates(hHandle);
		X509Certificate[] ret = null;
		if (handles != null)
		{
			ret = new X509Certificate[handles.length];
			for (int i = 0; i < handles.length; i++) ret[i] = new NharuX509Certificate(handles[i]);
		}
		return ret;
	}

	public boolean hasCertificatesAttached()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		return nhcmsHasCertificates(hHandle);
	}

	/**
	 * Verifies document signature. Only cryptographic signature is checked. To check signed attributes, use verify().
	 * @param store: trusted certificates store.
	 * @throws UntrustedCertificateException
	 * @throws CMSSignatureException
	 */
	private void verifySignature(final TrustedStore store) throws UntrustedCertificateException, CMSSignatureException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (store == null) throw new NullPointerException("Argument must not be null");
		final int count = countSigners();
		for (int i = 0; i < count; i++)
		{
			final NharuX509Certificate cert = (NharuX509Certificate) getSignerCertificate(i);
			if (!store.isTrusted(cert)) throw new UntrustedCertificateException();
			nhcmsVerify(hHandle, i, ((NharuRSAPublicKey) cert.getPublicKey()).getKeyHandle());
		}
	}

	/**
	 * Verifies this signed document. EncapsulatedContentInfo must be present.
	 * @param store: trusted certificates store.
	 * @throws UntrustedCertificateException
	 * @throws CMSSignatureException
	 * @throws CMSInvalidAttributesException
	 */
	public void verify(final TrustedStore store) throws UntrustedCertificateException, CMSSignatureException, CMSInvalidAttributesException
	{
		verifySignature(store);
		nhcmsValidateAttached(hHandle);
	}

	/**
	 * Verify this signed document using specified content
	 * @param eContent: EncapsulatedContentInfo eContent.
	 * @param store: trusted certificates store.
	 * @throws UntrustedCertificateException
	 * @throws CMSSignatureException
	 * @throws CMSInvalidAttributesException
	 */
	public void verify(final byte[] eContent, final TrustedStore store) throws UntrustedCertificateException, CMSSignatureException, CMSInvalidAttributesException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if(eContent == null) throw new NullPointerException("Arguments must not be null");
		verifySignature(store);
		nhcmsValidate(hHandle, eContent);
	}

	public void verfiy(final byte[] eContent, final CertificateResolver callback) throws CMSParsingException, CertificateException, CMSSignatureException, CMSInvalidAttributesException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		final int count = countSigners();
		for (int i = 0; i < count; i++)
		{
			final X509Certificate cert = callback.getCertificate(nhcmsGetSignerIdentifier(hHandle, i));
			if (cert == null) throw new CMSSignatureException("Signer certificate not provided");
			final NharuX509Certificate signerCert;
			if (!(cert instanceof NharuX509Certificate)) signerCert = NharuX509Factory.generateCertificate(cert.getEncoded());
			else signerCert = (NharuX509Certificate) cert;
			nhcmsVerify(hHandle, i, ((NharuRSAPublicKey) signerCert.getPublicKey()).getKeyHandle());
			nhcmsValidate(hHandle, eContent);
		}
	}

	/**
	 * Gets the number of signers of this CMS document.
	 * @return SignerInfos count.
	 */
	public int countSigners()
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (signers == 0) signers = nhcmsCountSigners(hHandle);
		return signers;
	}

	/**
	 * Gets the embedded certificate for specified signer info.
	 * @param idx: the signer info index.
	 * @return the signer certificate, if present.
	 */
	public X509Certificate getSignerCertificate(final int idx)
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		final long handle = nhcmsGetSignerCertificate(hHandle, idx);
		NharuX509Certificate cert = null;
		if (handle > 0) cert = new NharuX509Certificate(handle);
		return cert;
	}

	/**
	 * Releases native handler. Must be called once when object is no longer needed.
	 */
	public void releaseDocument()
	{
		if (hHandle != 0)
		{
			nhcmsReleaseHandle(hHandle);
			hHandle = 0;
		}
	}
	@Override
	public long getParentHandle(final X509FieldName node)
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		return nhcmsGetIssuerNode(hHandle);
	}
}
