package org.crypthing.security.issue;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import org.crypthing.security.EncodingException;
import org.crypthing.security.NharuRSAPublicKey;
import org.crypthing.security.NharuX500Name;
import org.crypthing.util.NharuCommon;
import org.json.JSONArray;
import org.json.JSONObject;

public class CertificateProfile
{
	private int version;
	private BigInteger serial;
	private int[] signatureAlgorithm;
	private NharuX500Name[] issuer;
	private Date notBefore;
	private Date notAfter;
	private NharuX500Name[] subject;
	private PublicKey publicKey;
	private byte[] aki;
	private byte[] keyUsage;
	private NharuOtherName[] subjectAltName;

	// TODO: Implements subjectKeyIdentifier and basicConstraints
	public CertificateProfile(final String profile) throws CertificateProfileException
	{
		try
		{
			final JSONObject json = new JSONObject(profile);
			setVersion(json.getInt("version"));
			setSerial(new BigInteger(fromHex(json.getString("serialNumber"))));

			JSONArray array = json.getJSONObject("signature").getJSONArray("algorithm");
			int[] algOID = new int[array.length()];
			for (int i = 0; i < array.length(); i++) algOID[i] = array.getInt(i);
			setSignatureAlgorithm(algOID);

			array = json.getJSONArray("issuer");
			NharuX500Name[] name = new NharuX500Name[array.length()];
			for (int i = 0; i < array.length(); i++) name[i] = NharuX500Name.parseJSON(array.getJSONObject(i).toString());
			setIssuer(name);

			setNotBefore(json.getJSONObject("validity").getString("notBefore"));
			setNotAfter(json.getJSONObject("validity").getString("notAfter"));

			array = json.getJSONArray("subject");
			name = new NharuX500Name[array.length()];
			for (int i = 0; i < array.length(); i++) name[i] = NharuX500Name.parseJSON(array.getJSONObject(i).toString());
			setSubject(name);

			setPublicKey(fromHex(json.getString("subjectPublicKeyInfo")));
			final JSONObject extensions = json.getJSONObject("extensions").getJSONObject("standard");
			setAKI(fromHex(extensions.getString("authorityKeyIdentifier")));
			setKeyUsage(fromHex(extensions.getString("keyUsage")));
		}
		catch (RuntimeException e) { throw new CertificateProfileException(e); }
	}

	/**
	 * <p>Creates a default certificate profile. The following values are default:</p>
	 * <ul>
	 * <li>version: 2 (v(3))</li>
	 * <li>signature algorithm: SHA256withRSA</li>
	 * <li>validity: 3 years from now</li>
	 * <li>key usage: Digital Signature, Non Repudiation, Key Encipherment</li>
	 * </ul>
	 */
	public CertificateProfile()
	{
		setVersion(2);
		setSignatureAlgorithm(new int[] { 1, 2, 840, 113549, 1, 1, 11 });
		final Date nob = new Date(System.currentTimeMillis());
		final Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
		cal.setTime(nob);
		cal.add(Calendar.YEAR, 3);
		setNotBefore(nob);
		setNotAfter(cal.getTime());
		setKeyUsage(fromHex("05E0"));
	}

	/**
	 * Gets certificate version
	 * @return the version
	 */
	public int getVersion() { return version; }
	/**
	 * Sets certificate version.
	 * @param version: the version to set. Must be 0, 1 or 2.
	 */
	public void setVersion(final int version) { if ((this.version = version) < 0 || this.version > 2) throw new RuntimeException("Invalid certificate version"); }

	/**
	 * Gets certificate serial number
	 * @return the serial
	 */
	public BigInteger getSerial() { return serial; }
	/**
	 * Sets certificate serial number
	 * @param serial the serial to set
	 */
	public void setSerial(final BigInteger serial) { this.serial = serial; }

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
	 * Gets certificate issuer
4	 * @return the X500 names array
	 */
	public NharuX500Name[] getIssuer() { return issuer; }
	/**
	 * Sets certificate issuer.
	 * @param name: issuer name array
	 */
	public void setIssuer(final NharuX500Name[] name) { issuer = name; }
	/**
	 * Sets certificate issuer.
	 * @param name: issuer name as specified by RFC 2253
	 */
	public void setIssuer(final String name) { issuer = parseName(name); }

	/**
	 * Gets validity start date
	 * @return initial validity
	 */
	public Date getNotBefore() { return notBefore; }
	/**
	 * Gets validity start date as a formatted string
	 * @return initial validity
	 */
	public String formatNotBefore()
	{
		if (notBefore == null) throw new RuntimeException("Instance field must not be null");
		return (new SimpleDateFormat("yyyyMMddHHmmssZ")).format(notBefore);
	}
	/**
	 * Sets validity start date
	 * @param date: initial validity
	 */
	public void setNotBefore(final Date date) { if ((notBefore = date) == null) throw new NullPointerException(); }
	/**
	 * Sets validity start date
	 * @param date: the date as a GeneralizedTime
	 */
	public void setNotBefore(final String date)
	{
		try { notBefore = (new SimpleDateFormat("yyyyMMddHHmmssZ")).parse(date); }
		catch (ParseException e) { throw new IllegalArgumentException(e); }
	}
	/**
	 * Gets validity end date
	 * @return final validity
	 */
	public Date getNotAfter() { return notAfter; }
	/**
	 * Sets validity end date
	 * @param date: final validity
	 */
	/**
	 * Gets validity end date as a formatted string
	 * @return final validity
	 */
	public String formatNotAfter()
	{
		if (notAfter == null) throw new RuntimeException("Instance field must not be null");
		return (new SimpleDateFormat("yyyyMMddHHmmssZ")).format(notAfter); 
	}
	public void setNotAfter(final Date date) { if ((notAfter = date) == null) throw new NullPointerException(); }
	/**
	 * Sets validity end date
	 * @param date: the date as a GeneralizedTime
	 */
	public void setNotAfter(final String date)
	{
		try { notAfter = (new SimpleDateFormat("yyyyMMddHHmmssZ")).parse(date); }
		catch (ParseException e) { throw new IllegalArgumentException(e); }
	}
	/**
	 * Gets certificate validity as a JSON object
	 * @return the object
	 */
	public String getValidity()
	{
		return (new StringBuilder(128))
			.append("{ \"notBefore\": \"")
			.append(formatNotBefore())
			.append("\", \"notAfter\": \"")
			.append(formatNotAfter())
			.append("\" }").toString();
	}

	/**
	 * Gets certificate subject
	 * @return the X500 names array
	 */
	public NharuX500Name[] getSubject() { return subject; }
	/**
	 * Sets certificate subject.
	 * @param name: subject name array
	 */
	public void setSubject(final NharuX500Name[] name) { subject = name; }
	/**
	 * Sets certificate subject.
	 * @param name: subject name as specified by RFC 2253
	 */
	public void setSubject(final String name) { subject = parseName(name); }

	/**
	 * Gets certificate public key info
	 * @return the public key
	 */
	public PublicKey getPublicKey() { return publicKey; }
	/**
	 * Sets certificate public key info
	 * @param key: the public key itself
	 */
	public void setPublicKey(final PublicKey key) { if ((publicKey = key) == null) throw new IllegalArgumentException("Argument must not be null"); }
	/**
	 * Sets certificate public key info
	 * @param encoding: PublicKeyInfo DER encoding
	 */
	public void setPublicKey(final byte[] encoding)
	{
		try { setPublicKey(new NharuRSAPublicKey(encoding)); }
		catch (EncodingException e) { throw new IllegalArgumentException(e); }
	}

	/**
	 * Gets AuthorityKeyIdentifier extension value
	 * @return: the extension value (before encoding)
	 */
	public byte[] getAKI() { return aki; }
	/**
	 * Sets AuthorityKeyIdentifier extension value
	 * @param aki: the extension value (before encoding)
	 */
	public void setAKI(final byte[] aki) { if ((this.aki = aki) == null) throw new IllegalArgumentException("Argument must not be null"); }
	/**
	 * Sets AuthorityKeyIdentifier extension value
	 * @param caCert: issuer certificate. Must embbeds SubjectKeyIdentifier extension. 
	 */
	public void setAKI(final X509Certificate caCert)
	{
		if (caCert.getBasicConstraints() < 0) throw new IllegalArgumentException("Certificate was not issued to a CA");
		final byte[] encoding = caCert.getExtensionValue("2.5.29.14");
		if (encoding == null) throw new IllegalArgumentException("Certificate does not embbeds a SubjectKeyIdentifier extension");
		if (encoding[0] != 0x04 || encoding[1] + 2 != encoding.length || encoding[2] != 0x04 || encoding[3] + 4 != encoding.length) throw new IllegalArgumentException("Invalid SubjectKeyIdentifier extension encoding");
		setAKI(Arrays.copyOfRange(encoding, 4, encoding.length));
	}

	/**
	 * Gets KeyUsage extension value
	 * @return: extension value. The first byte represents the number of unsed bits.
	 */
	public byte[] getKeyUsage() { return keyUsage; }
	/**
	 * Sets KeyUsage extension value
	 * @param value: extension value bitmap
	 */
	public void setKeyUsage(final byte[] value) { if ((keyUsage = value) == null ||  keyUsage.length > 3) throw new IllegalArgumentException("Argument must conform KeyUsage extension encoding"); }
	/**
	 * Sets KeyUsage extension value
	 * @param value: extension value as an array of boolean
	 */
	public void setKeyUsage(final boolean[] value)
	{
		if (value == null || value.length != 9) throw new IllegalArgumentException("Argument must conform KeyUsage extension bit map");
		byte first = 0x00, second = 0x00;
		int i = 0, unused = 9, mask = 0x80;
		while (i < value.length)
		{
			if (value[i])
			{
				if (i < 8) first |= mask >> i;
				else second |= 1 << 7;
				unused--;
			}
			i++;
		}
		final byte[] keyUsage = new byte[second > 0 ? 3 : 2];
		keyUsage[0] = (byte) unused;
		keyUsage[1] = first;
		if (second > 0) keyUsage[2] = second;
		setKeyUsage(keyUsage);
	}

	private static final char[] HEX = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	private String toHex(final byte[] bin)
	{
		if (bin == null || bin.length == 0) throw new IllegalArgumentException("Argument must not be null");
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
		if (hex == null || hex.length() % 2 != 0) throw new NumberFormatException();
		final byte[] out = new byte[hex.length() / 2];
		for (int i = 0; i < hex.length(); i += 2) out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
		return out;
	}
	private NharuX500Name[] parseName(final String name)
	{
		if (name == null) throw new NullPointerException();
		final String[] parts = name.split(",");
		final NharuX500Name[] names = new NharuX500Name[parts.length];
		for (int i = 0; i < parts.length; i++) names[i] = new NharuX500Name(parts[i]);
		return names;
	}



	public static void main(String[] args)
	{
	}
}
