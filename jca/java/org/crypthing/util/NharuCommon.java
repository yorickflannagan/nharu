package org.crypthing.util;

import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;


/**
 * Just some utilities.
 * @author magut
 *
 */
public final class NharuCommon
{
	
	public static boolean[] bitmapToBoolArray(final byte[] bitmap)
	{
		final boolean[] ret = new boolean[(bitmap.length - 1) * Byte.SIZE];
		int j = 0;
		for (int i = 1; i < bitmap.length; i++ ) for (int b = 0x80; b != 0; b >>=  0x01) ret[j++] = (b & bitmap[i]) != 0;
		return ret;
	}

	public static String oidToString(final int[] oid)
	{
		final StringBuilder builder = new StringBuilder(32);
		for (int i = 0; i < oid.length; i++)
		{
			builder.append(oid[i]);
			builder.append('.');
		}
		return builder.substring(0, builder.length() - 1);
	}

	public static String oidToString(final Integer[] oid)
	{
		final int[] iOID = new int[oid.length];
		for (int i = 0; i < oid.length; i++) iOID[i] = oid[i];
		return oidToString(iOID);
	}

	public static int[] stringToOID(final String oid)
	{
		String[] id = oid.split("\\.");
		final int[] ret = new int[id.length];
		for (int i = 0; i < id.length; i++)
		{
			try
			{
				ret[i] = Integer.parseInt(id[i]);
			}
			catch (final NumberFormatException swallowed) { return null; }
		}
		return ret;
	}

	/*
	 * java.security.Signature algorithm constants
	 */
	public static final int NHIX_NONEwithRSA_ALGORITHM = 1;
	public static final int NHIX_MD2withRSA_ALGORITHM = 2;
	public static final int NHIX_MD5withRSA_ALGORITHM = 3;
	public static final int NHIX_SHA1withRSA_ALGORITHM = 4;
	public static final int NHIX_SHA256withRSA_ALGORITHM = 5;
	public static final int NHIX_SHA384withRSA_ALGORITHM = 6;
	public static final int NHIX_SHA512withRSA_ALGORITHM = 7;
	public static final int NHIX_NONEwithDSA_ALGORITHM = 8;
	public static final int NHIX_SHA1withDSA_ALGORITHM = 9;
	public static final int NHIX_NONEwithECDSA_ALGORITHM = 10;
	public static final int NHIX_SHA1withECDSA_ALGORITHM = 11;
	public static final int NHIX_SHA256withECDSA_ALGORITHM = 12;
	public static final int NHIX_SHA384withECDSA_ALGORITHM = 13;
	public static final int NHIX_SHA512withECDSA_ALGORITHM = 14;
	public static String getAlgorithmName(int nhixConst)
	{
		String ret = "";
		switch (nhixConst)
		{
		case NHIX_NONEwithRSA_ALGORITHM:
			ret = "NONEwithRSA";
			break;
		case NHIX_MD2withRSA_ALGORITHM:
			ret = "MD2withRSA";
			break;
		case NHIX_MD5withRSA_ALGORITHM:
			ret = "MD5withRSA";
			break;
		case NHIX_SHA1withRSA_ALGORITHM:
			ret = "SHA1withRSA";
			break;
		case NHIX_SHA256withRSA_ALGORITHM:
			ret = "SHA256withRSA";
			break;
		case NHIX_SHA384withRSA_ALGORITHM:
			ret = "SHA384withRSA";
			break;
		case NHIX_SHA512withRSA_ALGORITHM:
			ret = "SHA512withRSA";
			break;
		case NHIX_NONEwithDSA_ALGORITHM:
			ret = "NONEwithDSA";
			break;
		case NHIX_SHA1withDSA_ALGORITHM:
			ret = "SHA1withDSA";
			break;
		case NHIX_NONEwithECDSA_ALGORITHM:
			ret = "NONEwithECDSA";
			break;
		case NHIX_SHA1withECDSA_ALGORITHM:
			ret = "SHA1withECDSA";
			break;
		case NHIX_SHA256withECDSA_ALGORITHM:
			ret = "SHA256withECDSA";
			break;
		case NHIX_SHA384withECDSA_ALGORITHM:
			ret = "SHA384withECDSA";
			break;
		case NHIX_SHA512withECDSA_ALGORITHM:
			ret = "SHA512withECDSA";
			break;
		default: throw new RuntimeException("Improper algorithm constant");
		}
		return ret;
	}

	public static final int CKM_SHA1_RSA_PKCS = 0x00000006;
	public static final int CKM_SHA256_RSA_PKCS = 0x00000040;
	public static final int CKM_SHA384_RSA_PKCS = 0x00000041;
	public static final int CKM_SHA512_RSA_PKCS = 0x00000042;
	public static final int CKM_MD5_RSA_PKCS = 0x00000005;
	public static final int CKM_RSA_PKCS = 0x00000001;
	public static final int CKM_RSA_PKCS_OAEP = 0x00000009;
	public static final int CKM_RSA_X_509 = 0x00000003;
	public static int getAlgorithmConstant(final String algorithm) throws NoSuchAlgorithmException
	{
		if ("SHA1withRSA".equalsIgnoreCase(algorithm)) return CKM_SHA1_RSA_PKCS;
		if ("SHA256withRSA".equalsIgnoreCase(algorithm)) return CKM_SHA256_RSA_PKCS;
		if ("SHA384withRSA".equalsIgnoreCase(algorithm)) return CKM_SHA384_RSA_PKCS;
		if ("SHA512withRSA".equalsIgnoreCase(algorithm)) return CKM_SHA512_RSA_PKCS;
		if ("MD5withRSA".equalsIgnoreCase(algorithm)) return CKM_MD5_RSA_PKCS;
		if ("PKCS1Padding".equalsIgnoreCase(algorithm)) return CKM_RSA_PKCS;
		if ("OAEPPadding".equalsIgnoreCase(algorithm)) return CKM_RSA_PKCS_OAEP;
		if ("NoPadding".equalsIgnoreCase(algorithm)) return CKM_RSA_X_509;
		throw new NoSuchAlgorithmException("Unsupported algorithm");
	}

	public static int getIntSize(int value)
	{
		return (value < 0x00000080) ? 1 : (value < 0x00000100) ? 2 : (value < 0x00010000) ? 3 : (value < 0x01000000) ? 4 : 5;
	}

	public static void writeASNInt(final int value, int len, final OutputStream os) throws IOException
	{
		if (value > 0x7F) os.write(0x80 | --len);
		int mask = 0xFF000000 >> (4 - len) * 8;
		while (len > 0)
		{
			len--;
			os.write(((mask & value) >> (8 * len)));
			mask >>= 8;
		}
	}

}
