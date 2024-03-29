package org.crypthing.security.cms;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.crypthing.security.NharuRSAPublicKey;
import org.crypthing.security.cert.TrustedStore;
import org.crypthing.security.provider.NharuProvider;
import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.security.x509.NharuX509Factory;

/**
 * Parses a CMS SignedData document
 * @author magut
 *
 */
public final class CMSSignedData
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
	private static native SignerIdentifier nhcmsGetSignerIdentifier(long handle, int idx) throws CMSParsingException;
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
			nhcmsVerify(hHandle, i, ((NharuRSAPublicKey) cert.getPublicKey()).getInternalNode());
		}
	}

	/**
	 * Verifies attached document signature and checks signed attribute eContent.
	 * Ignores signer certificate trustworthiness.
	 * @throws CMSSignatureException if cryptographic validation fails.
	 * @throws CMSInvalidAttributesException if encapsulated content info validation fails.
	 * @since 1.7.0
	 */
	public void verify() throws CMSSignatureException, CMSInvalidAttributesException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		final int count = countSigners();
		for (int i = 0; i < count; i++)
		{
			final NharuX509Certificate cert = (NharuX509Certificate) getSignerCertificate(i);
			nhcmsVerify(hHandle, i, ((NharuRSAPublicKey) cert.getPublicKey()).getInternalNode());
			nhcmsValidateAttached(hHandle);
		}
	}

	/**
	 * Verifies CMS document signature of detached content and and checks signed attribute eContent.
	 * Ignores signer certificate trustworthiness.
	 * @param eContent signed content
	 * @throws CMSSignatureException if cryptographic validation fails.
	 * @throws CMSInvalidAttributesException if encapsulated content info validation fails.
	 * @since 1.7.0
	 */
	public void verify(final byte[] eContent) throws CMSSignatureException, CMSInvalidAttributesException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if(eContent == null) throw new NullPointerException("Arguments must not be null");
		final int count = countSigners();
		for (int i = 0; i < count; i++)
		{
			final NharuX509Certificate cert = (NharuX509Certificate) getSignerCertificate(i);
			nhcmsVerify(hHandle, i, ((NharuRSAPublicKey) cert.getPublicKey()).getInternalNode());
			nhcmsValidate(hHandle, eContent);
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

	public void verify(final byte[] eContent, final CertificateResolver callback) throws CMSParsingException, CertificateException, CMSSignatureException, CMSInvalidAttributesException
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
			nhcmsVerify(hHandle, i, ((NharuRSAPublicKey) signerCert.getPublicKey()).getInternalNode());
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


	private static final String INVALID_ARG = "Argument must point to CMS documents folder";
	private static final String INVALID_FOLDER = INVALID_ARG + " where the following file must exists: ";
	private static final String ATTACHED = "attached-cms.pem";
	private static final String DETACHED = "dettached-cms.pem";
	private static final String ECONTENT = "conteudo assinado";
	private static File checkArgs(String[] args)
	{
		if (args.length == 0) throw new RuntimeException(INVALID_ARG);
		final File folder = new File(args[0]);
		if (!folder.isDirectory()) throw new RuntimeException(INVALID_ARG);
		File child = new File(folder, ATTACHED);
		if (!child.canRead()) throw new RuntimeException(INVALID_FOLDER + ATTACHED);
		child = new File(folder, DETACHED);
		if (!child.canRead()) throw new RuntimeException(INVALID_FOLDER + DETACHED);
		return folder;
	}
	private static byte[] open(final File parent, final String child) throws IOException
	{
		byte[] ret = null;
		final FileInputStream in = new FileInputStream(new File(parent, child));
		try
		{
			final ByteArrayOutputStream out = new ByteArrayOutputStream(4096);
			byte[] buffer = new byte[1024];
			int read;
			while ((read = in.read(buffer)) != -1) out.write(buffer, 0, read);
			ret = out.toByteArray();
		}
		finally { in.close(); }
		return ret;
	}
	private static void checkAttached(final File parent) throws IOException, CMSException
	{
		System.out.println("Attached CMS signed document cryptographic validation test...");
		byte[] input = open(parent, ATTACHED);
		final CMSSignedData doc = new CMSSignedData(input);
		try { doc.verify(); }
		finally { doc.releaseDocument(); }
		System.out.println("Test done!");
	}
	public static void checkDetached(final File parent) throws IOException, CMSException
	{
		System.out.println("Detached CMS signed document cryptographic validation test...");
		byte[] input = open(parent, DETACHED);
		final CMSSignedData doc = new CMSSignedData(input);
		try { doc.verify(ECONTENT.getBytes()); }
		finally { doc.releaseDocument(); }
		System.out.println("Test done!");
	}
	public static void main(String[] args) throws Exception
	{
		System.out.println("===================================");
		System.out.println("Version 1.7.0 validation check...");
		System.out.println("===================================");
		final File folder = checkArgs(args);
		checkAttached(folder);
		checkDetached(folder);
		System.out.println("Version 1.7.0 check done");
	}
}
