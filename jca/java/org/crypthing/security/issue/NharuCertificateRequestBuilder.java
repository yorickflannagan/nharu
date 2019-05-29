package org.crypthing.security.issue;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

import org.crypthing.security.EncodingException;
import org.crypthing.security.NharuX500Name;
import org.crypthing.security.SignerInterface;
import org.crypthing.security.provider.NharuProvider;
import org.crypthing.util.NharuCommon;

public class NharuCertificateRequestBuilder
{
	static { NharuProvider.isLoaded(); }
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws NotSerializableException { throw new NotSerializableException(); }
	private void readObjectNoData() throws ObjectStreamException { throw new NotSerializableException(); }

	private long hHandle;
	private NharuX500Name[] subject;
	private PublicKey pubKey;
	private boolean signed = false;
	private byte[] encoding;
	public NharuCertificateRequestBuilder() { hHandle = nhceNewRequestBuilder(); }
	public void release() { if (hHandle != 0) { nhceReleaseRequestBuilder(hHandle); hHandle = 0; }}
	public NharuX500Name[] getSubject() { return subject; }
	public void setSubject(final String dn)
	{
		if (subject != null) throw new IllegalStateException("Property already set");
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		subject = CertificateParams.parseName(dn);
		nhceSetSubject(hHandle, subject);
	}
	public PublicKey getPublicKey() { return pubKey; }
	public void setPublicKey(final PublicKey key) throws EncodingException
	{
		if (pubKey != null) throw new IllegalStateException("Property already set");
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		nhceSetPubKey(hHandle, (pubKey = key).getEncoded());
	}
	public void sign(final String algorithm, final SignerInterface signer) throws GeneralSecurityException
	{
		if (subject == null || pubKey == null) throw new IllegalStateException("Request not built yet");
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (signed) throw new IllegalStateException("Request already signed");
		nhceSignRequest(hHandle, NharuCommon.getAlgorithmConstant(algorithm), signer);
		signed = true;
	}
	public byte[] getEncoded()
	{
		if (encoding == null)
		{
			if (hHandle == 0) throw new IllegalStateException("Object already released");
			if (!signed) throw new IllegalStateException("Request not signed yet");
			encoding = nhceEncodeRequest(hHandle);
		}
		return encoding;
	}
	
	private static native long nhceNewRequestBuilder();
	private static native void nhceReleaseRequestBuilder(long hHandle);
	private static native void nhceSetSubject(long hHandle, NharuX500Name[] name);
	private static native void nhceSetPubKey(long hHandle, byte[] encoding) throws EncodingException;
	private static native void nhceSignRequest(long hHandle, int mechanism, SignerInterface signer) throws GeneralSecurityException;
	private static native byte[] nhceEncodeRequest(long hHandle);
}