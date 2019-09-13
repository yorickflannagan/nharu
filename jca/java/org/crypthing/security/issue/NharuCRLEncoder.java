package org.crypthing.security.issue;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import org.crypthing.security.EncodingException;
import org.crypthing.security.NharuRSAPrivateKey;
import org.crypthing.security.NharuRSAPublicKey;
import org.crypthing.security.NharuX500Name;
import org.crypthing.security.SignerInterface;
import org.crypthing.security.provider.NharuProvider;
import org.crypthing.security.x509.NharuX509CRL;
import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.util.NharuCommon;

public class NharuCRLEncoder
{
	public static enum CRLReason
	{
		unspecified             (0),
		keyCompromise           (1),
		cACompromise            (2),
		affiliationChanged      (3),
		superseded              (4),
		cessationOfOperation    (5),
		certificateHold         (6),
		removeFromCRL           (8),
		privilegeWithdrawn      (9),
		aACompromise           (10);
		private final int value;
		CRLReason(int i)	{ value = i; }
		public int getReason() { return value; }
	}
	static { NharuProvider.isLoaded();}
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws NotSerializableException { throw new NotSerializableException(); }

	private static final int ISSUER_SETTED		= 1;
	private static final int AKI_SETTED			= (ISSUER_SETTED << 1);
	private static final int CRL_NUMBER_SETTED	= (ISSUER_SETTED << 2);
	private static final int THIS_UPDATED_SETTED	= (ISSUER_SETTED << 3);
	private static final int NEXT_UPDATED_SETTED	= (ISSUER_SETTED << 4);
	private static final int SIGN_SETTED		= (ISSUER_SETTED << 5);
	private static final int READY_TO_SIGN		= 0x1F;
	private static final int READY_TO_ENCODE		= 0x3F;
	private long hHandle = 0;
	private int fields = 0;
	private byte[] encoding;
	public NharuCRLEncoder() { hHandle = nhclNewCRLEncoder(); }
	public NharuCRLEncoder(final NharuX509Certificate issuer) throws ParameterException { this(); setIssuer(issuer); }
	public void releaseObject()
	{
		if (hHandle != 0)
		{
			nhclReleaseCRLEncoder(hHandle);
			hHandle = 0;
		}
	}
	public void setIssuer(final NharuX509Certificate issuer) throws ParameterException
	{
		if (__is_set(ISSUER_SETTED) || __is_set(AKI_SETTED)) throw new IllegalStateException("Property already setted");
		if (issuer == null) throw new NullPointerException();
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		final String [] s = issuer.getIssuerX500Principal().getName().split(",");
		final StringBuilder sb = new StringBuilder(s.length);
		for(int i = s.length-1; i > 0; i--) sb.append(s[i]).append(','); 
		nhclSetIssuer(hHandle, CertificateParams.parseName(sb.append(s[0]).toString()));
		fields |= ISSUER_SETTED;
		if (!(issuer.getPublicKey() instanceof NharuRSAPublicKey)) throw new IllegalArgumentException("Unsupported Public Key type");
		nhclSetAKI(hHandle, ((NharuRSAPublicKey)issuer.getPublicKey()).getKeyIdentifier());
		fields |= AKI_SETTED;
	}
	public void setCRLNumber(final BigInteger number) throws ParameterException
	{
		if (number == null) throw new NullPointerException();
		if (__is_set(CRL_NUMBER_SETTED)) throw new IllegalStateException("Property already setted");
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		nhclSetCRLNumber(hHandle, number.toByteArray());
		fields |= CRL_NUMBER_SETTED;
	}
	public void setThisUpdate(final Date instant) throws ParameterException
	{
		if (__is_set(THIS_UPDATED_SETTED)) throw new IllegalStateException("Property already setted");
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		nhclSetThisUpdate(hHandle, __format(instant));
		fields |= THIS_UPDATED_SETTED;
	}
	public void setNextUpdate(final Date instant) throws ParameterException
	{
		if (__is_set(NEXT_UPDATED_SETTED)) throw new IllegalStateException("Property already setted");
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		nhclSetNextUpdate(hHandle, __format(instant));
		fields |= NEXT_UPDATED_SETTED;
	}
	public void addCert(final BigInteger serial, final Date revoked, final CRLReason reason) throws ParameterException
	{
		if (serial == null) throw new NullPointerException();
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		nhclAddCert(hHandle, serial.toByteArray(), __format(revoked), reason.getReason());
	}
	public void sign(final String algorithm, final SignerInterface signer) throws GeneralSecurityException
	{
		if (signer == null) throw new NullPointerException();
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (__is_set(SIGN_SETTED)) throw new IllegalStateException("CRL already signed");
		if (fields != READY_TO_SIGN) throw new IllegalStateException("CRL not ready to sign");
		nhclSign(hHandle, NharuCommon.getAlgorithmConstant(algorithm), signer);
		fields |= SIGN_SETTED;
	}
	public byte[] encode() throws EncodingException
	{
		if (encoding == null)
		{
			if (fields != READY_TO_ENCODE) throw new IllegalStateException("CRL not signed");
			if (hHandle == 0) throw new IllegalStateException("Object already released");
			encoding = nhclEncode(hHandle);
		}
		return encoding;
	}
	private boolean __is_set(final int a) { return (a & fields) == a; }
	private String __format(final Date instant)
	{
		if (instant == null) throw new NullPointerException();
		SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmmssX");
		df.setTimeZone(TimeZone.getTimeZone("GMT"));
		return df.format(instant);
	}


	private static native long nhclNewCRLEncoder();
	private static native void nhclReleaseCRLEncoder(long handle);
	private static native void nhclSetIssuer(long handle, NharuX500Name[] value) throws ParameterException;
	private static native void nhclSetAKI(long handle, byte[] value) throws ParameterException;
	private static native void nhclSetCRLNumber(long handle, byte[] value) throws ParameterException;
	private static native void nhclSetThisUpdate(long handle, String value) throws ParameterException;
	private static native void nhclSetNextUpdate(long handle, String value) throws ParameterException;
	private static native void nhclAddCert(long handle, byte[] serial, String revoked, int reason) throws ParameterException;
	private static native void nhclSign(long handle, int mechanism, SignerInterface signer) throws GeneralSecurityException;
	private static native byte[] nhclEncode(long handle) throws EncodingException;



	public static void main(String[] args)
	{
		System.out.print("Validating CRL issuing...");
		BigInteger revoked = new BigInteger("128");
		BigInteger another = new BigInteger("32768");
		try
		{
			NharuX509Certificate caCert = new NharuX509Certificate(NharuCertificateEncoder.CA_CERT.getBytes());
			try
			{
				NharuCRLEncoder hCRL = new NharuCRLEncoder(caCert);
				try
				{
					Date now = new Date(System.currentTimeMillis());
					hCRL.setThisUpdate(now);
					final Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
					cal.setTime(now);
					cal.add(Calendar.HOUR, 1);
					hCRL.setNextUpdate(cal.getTime());
					hCRL.setCRLNumber(BigInteger.ONE);
					hCRL.addCert(revoked, now, CRLReason.keyCompromise);
					hCRL.addCert(another, now, CRLReason.cACompromise);
					NharuRSAPrivateKey caKey = new NharuRSAPrivateKey(NharuCertificateEncoder.CA_KEY);
					try
					{
						hCRL.sign("SHA256withRSA", caKey);
						NharuX509CRL crl = new NharuX509CRL(hCRL.encode());
						try
						{
							crl.verify(caCert.getPublicKey());
							if (!crl.isRevoked(revoked.toByteArray()) || !crl.isRevoked(another.toByteArray())) throw new RuntimeException("Check certificates not found in CRL");
							System.out.println("Done!");
						}
						finally { crl.closeHandle(); }
					}
					finally { caKey.releaseObject(); }
				}
				finally { hCRL.releaseObject(); }
			}
			finally { caCert.closeHandle(); }
		}
		catch (Exception e) { System.out.println(""); e.printStackTrace(); }
	}
}
