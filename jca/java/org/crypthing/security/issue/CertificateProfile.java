package org.crypthing.security.issue;

import java.math.BigInteger;

import org.crypthing.util.NharuCommon;
import org.json.JSONArray;
import org.json.JSONObject;

public class CertificateProfile
{
	private int version;
	private BigInteger serial;
	private int[] signatureAlgorithm;

	CertificateProfile(final String profile) throws CertificateProfileException
	{
		try
		{
			final JSONObject json = new JSONObject(profile);
			setVersion(json.getInt("version"));
			setSerial(new BigInteger(fromHex(json.getString("serialNumber"))));
			JSONArray alg = json.getJSONObject("signature").getJSONArray("algorithm");
			int[] algOID = new int[alg.length()];
			for (int i = 0; i < alg.length(); i++) algOID[i] = alg.getInt(i);
			setSignatureAlgorithm(algOID);
		}
		catch (RuntimeException e)
		{
			throw new CertificateProfileException(e);
		}
	}

	/**
	 * Gets certificate signature algorithm OID
	 * @return the signatureAlgorithm
	 */
	public int[] getSignatureAlgorithm() { return signatureAlgorithm; }

	/**
	 * Sets certificate signagure algorithm
	 * @param signatureAlgorithm the signatureAlgorithm
	 */
	public void setSignatureAlgorithm(final int[] signatureAlgorithm) { this.signatureAlgorithm = signatureAlgorithm; }
	/**
	 * Sets certificate signagure algorithm
	 * @param signatureAlgorithm the signatureAlgorithm to set as an OID
	 */
	public void setSignatureAlgorithm(final String signatureAlgorithm) { this.signatureAlgorithm = NharuCommon.stringToOID(signatureAlgorithm); }

	/**
	 * Sets certificate signagure algorithm
	 * @param name the signatureAlgorithm as a java name
	 */
	public void setSignatureAlgorithmByName(final String name)
	{
		if (name.equalsIgnoreCase("SHA256withRSA")) setSignatureAlgorithmByName("1.2.840.113549.1.1.11");
		else if (name.equalsIgnoreCase("SHA1withRSA")) setSignatureAlgorithmByName("1.3.14.3.2.29");
		else if (name.equalsIgnoreCase("SHA384withRSA")) setSignatureAlgorithmByName("1.2.840.113549.1.1.12");
		else if (name.equalsIgnoreCase("SHA512withRSA")) setSignatureAlgorithmByName("1.2.840.113549.1.1.13");
		else if (name.equalsIgnoreCase("MD5withRSA")) setSignatureAlgorithmByName("1.3.14.3.2.3");
		else throw new RuntimeException("Unsupported signature algorithm");
	}

	/**
	 * Gets certificate serial number
	 * 
	 * @return the serial
	 */
	public BigInteger getSerial() { return serial; }

	/**
	 * Sets certificate serial number
	 * @param serial the serial to set
	 */
	public void setSerial(BigInteger serial) { this.serial = serial; }

	/**
	 * Gets certificate version
	 * 
	 * @return the version
	 */
	public int getVersion() { return version; }

	/**
	 * Sets certificate version. 
	 * @param version: the version to set. Must be 0, 1 or 2.
	 */
	public void setVersion(final int version) { if ((this.version = version) < 0 || this.version > 2) throw new RuntimeException("Invalid certificate version"); }

	public CertificateProfile()
	{
		
	}

	private static final char[] HEX = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	private String toHex(final byte[] bin)
	{
		final char[] out = new char[bin.length * 2];
		for (int i = 0; i < bin.length; i++)
		{
			out[i * 2    ] = HEX[bin[i] >> 4  ];
			out[i * 2 + 1] = HEX[bin[i] & 0x0F];
		}
		return new String(out);
	}
	private byte[] fromHex(final String hex)
	{
		if (hex.length() % 2 != 0) throw new NumberFormatException();
		final byte[] out = new byte[hex.length() / 2];
		for (int i = 0; i < hex.length(); i += 2) out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
		return out;
	}
	public static void main(String[] args)
	{
	}
}
