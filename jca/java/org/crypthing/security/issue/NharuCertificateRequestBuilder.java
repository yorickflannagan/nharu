package org.crypthing.security.issue;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Calendar;
import java.util.TimeZone;

import org.crypthing.security.EncodingException;
import org.crypthing.security.NharuRSAKeyPairGenerator;
import org.crypthing.security.NharuRSAPrivateKey;
import org.crypthing.security.NharuRSAPublicKey;
import org.crypthing.security.NharuX500Name;
import org.crypthing.security.SignerInterface;
import org.crypthing.security.provider.NharuProvider;
import org.crypthing.security.x509.NharuX509Certificate;
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


	public static void main(String[] args)
	{
		System.out.println("Validating self-signed certificate issue...");
		try
		{
			KeyPairGenerator keyGen = new NharuRSAKeyPairGenerator();
			KeyPair pair = keyGen.generateKeyPair();
			NharuRSAPublicKey pubKey = (NharuRSAPublicKey) pair.getPublic();
			try
			{
				NharuRSAPrivateKey privKey = (NharuRSAPrivateKey) pair.getPrivate();
				try
				{
					NharuCertificateRequestBuilder request = new NharuCertificateRequestBuilder();
					try
					{
						request.setSubject("C=BR, O=PKI Brazil, OU=PKI Ruler for All Cats, CN=Common Name for All Cats Root CA");
						request.setPublicKey(pubKey);
						request.sign("SHA256withRSA", privKey);
						NharuCertificateRequest toSign = NharuCertificateRequest.parse(request.getEncoded());
						try
						{
							toSign.verify();
							CertificateParams params = new CertificateParams();
							Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
							cal.setTime(params.getNotBefore());
							cal.add(Calendar.YEAR, 9);
							params.setNotAfter(cal.getTime());
							params.setKeyUsage(new boolean[] { false, false, false, false, false, true, true, false, false });
							params.setSerial(BigInteger.ONE);
							params.setIssuer("C=BR, O=PKI Brazil, OU=PKI Ruler for All Cats, CN=Common Name for All Cats Root CA");
							params.setSubject(toSign.getSubject().getName());
							params.setPublicKey(toSign.getPublicKey());
							params.setAKI(pubKey.getKeyIdentifier());
							params.setCDP(new String[] { "http://localhost/ac/root.crl" });
							params.turnonBasicConstraints();
							params.setSKI(pubKey.getKeyIdentifier());
							NharuCertificateEncoder cert = new NharuCertificateEncoder(params, new CAProfile());
							try
							{
								cert.sign("SHA256withRSA", privKey);
								NharuX509Certificate root = new NharuX509Certificate(cert.encode());
								try
								{
									root.checkValidity();
									root.verify(pubKey);
									System.out.println("Done!");
								}
								finally { root.closeHandle(); }
							}
							finally { cert.releaseObject(); }
						}
						finally { toSign.releaseObject(); }
					}
					catch (GeneralSecurityException e) { throw new RuntimeException(e); }
					finally { request.release(); }
				}
				finally { privKey.releaseObject(); }
			}
			finally { pubKey.releaseObject(); }
		}
		catch (Exception e) { e.printStackTrace(); }
	}
}