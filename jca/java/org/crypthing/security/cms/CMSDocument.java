package org.crypthing.security.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.crypthing.security.cert.NharuCertStore;
import org.crypthing.security.provider.NharuProvider;
import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.security.x509.NharuX509Factory;
import org.crypthing.util.NharuArrays;

/**
 * CMS parsing facility
 * @author magut
 *
 */
public abstract class CMSDocument
{
	static { NharuProvider.isLoaded(); }
	enum CMSContentType
	{
		NH_UNKNOWN_CTYPE,
		NH_DATA_CTYPE,
		NH_SIGNED_DATA_CTYPE,
		NH_ENVELOPED_DATA_CTYPE,
		NH_DIGESTED_DATA_CTYPE,
		NH_ENCRYPTED_DATA_CTYPE,
		NH_AUTH_DATA_CTYPE;
		int getValue() { return ordinal() - 1; }
		public static CMSContentType getContentType(final int type)
		{
			switch (type)
			{
			case 0: return NH_DATA_CTYPE;
			case 1: return NH_SIGNED_DATA_CTYPE;
			case 2: return NH_ENVELOPED_DATA_CTYPE;
			case 3: return NH_DIGESTED_DATA_CTYPE;
			case 4: return NH_ENCRYPTED_DATA_CTYPE;
			case 5: return NH_AUTH_DATA_CTYPE;
			default: return NH_UNKNOWN_CTYPE;
			}
		}
	}

	/**
	 * Parses specified encoding into a CMS document. Only SignedData and EnvelopedData are currently supported.
	 * @param encoding - PEM or DER encoded CMS
	 * @return the proper type.
	 * @throws CMSException if could not parse encoding.
	 */
	@SuppressWarnings("unchecked")
	public static <T> T parse(final byte[] encoding) throws CMSException
	{
		switch (CMSContentType.getContentType(nhcmsDiscover(encoding)))
		{
		case NH_SIGNED_DATA_CTYPE: return (T) new CMSSignedData(encoding);
		case NH_ENVELOPED_DATA_CTYPE: return (T) new CMSEnvelopedData(encoding);
		case NH_UNKNOWN_CTYPE: throw new CMSParsingException("Invalid CMS document");
		default: throw new UnsupportedCMSTypeException();
		}
	}

	private static native int nhcmsDiscover(byte[] encoding);




	/*
	 * Basic tests
	 * ==================================
	 */
	private static boolean signTest()
	{
		boolean ret = false;
		System.out.print("CMSSignedData signature test... ");
		try
		{
			final NharuKeyStore signer = NharuKeyStore.getInstance();
			try
			{
				final CMSSignedDataBuilder builder = new CMSSignedDataBuilder("eContent".getBytes(), true);
				try
				{
					final NharuX509Certificate[] chain = signer.getSignerChain();
					if (chain == null) throw new RuntimeException("BlindSigner not configured properly");
					builder.addCertificates(chain);
					builder.sign("SHA1withRSA", chain[0], signer);
					final byte[] encoding = builder.encode();
					try
					{
						final NharuCertStore trusted = NharuCertStore.getInstance();
						CMSSignedData doc;
						try
						{
							doc = new CMSSignedData(encoding);
							try
							{
								doc.verify(trusted);
								System.out.println("Done!");
								ret = true;
							}
							finally { doc.releaseDocument(); }
						}
						catch (final CMSParsingException e) { e.printStackTrace(); }
					}
					catch (final GeneralSecurityException e) { e.printStackTrace(); }
				}
				finally { builder.releaseBuilder(); }
			}
			finally { signer.releaseObject(); }
		}
		catch (final GeneralSecurityException e) { e.printStackTrace(); }
		return ret;
	}
	private static final byte[] PLAIN_TEXT = "eContent".getBytes();
	private static boolean encryptTest()
	{
		boolean ret = false;
		System.out.print("CMSEnvelolpedData encryption document test... ");
		try
		{
			final NharuKeyStore recip = NharuKeyStore.getInstance();
			try
			{
				final NharuX509Certificate[] chain = recip.getSignerChain();
				if (chain == null) throw new RuntimeException("Encryption not configured properly");
				try
				{
					final CMSEnvelopedDataBuilder builder = new CMSEnvelopedDataBuilder(PLAIN_TEXT);
					try
					{
						builder.encrypt("DESede", 24, "DESede-CBC");
						builder.addKeyTransRecip(chain[0], "OAEPPadding");
						final byte[] encoding = builder.encode();
						final CMSEnvelopedData document = new CMSEnvelopedData(encoding);
						try
						{
							try
							{
								if (!NharuArrays.equals(PLAIN_TEXT, document.decrypt(recip))) throw new RuntimeException("Encrypted document does not match");
								System.out.println("Done!");
								ret = true;
							}
							catch (final CMSException e) { e.printStackTrace(); }
						} 
						finally { document.releaseDocument(); }
					}
					catch (final CMSEncryptException | NoSuchAlgorithmException | UnrecoverableKeyException e) { e.printStackTrace(); }
					finally { builder.releaseBuilder(); }
				}
				catch (final CMSParsingException e) { e.printStackTrace(); }
			}
			finally { recip.releaseObject(); }
		}
		catch (final GeneralSecurityException e) { e.printStackTrace(); }
		return ret;
	}
	public static void main(final String[] args)
	{
		boolean success = signTest();
		if (success) success = encryptTest();
	}
}
