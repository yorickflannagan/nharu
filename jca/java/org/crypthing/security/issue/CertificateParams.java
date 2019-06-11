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
import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.util.NharuCommon;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Parameters to certificate issuing.
 * @since 1.3.0
 */
public class CertificateParams
{
	private int version;
	private BigInteger serial;
	private int[] signatureAlgorithm;
	private NharuX500Name[] issuer;
	private Date notBefore;
	private Date notAfter;
	private NharuX500Name[] subject;
	private NharuRSAPublicKey publicKey;
	private byte[] aki;
	private byte[] keyUsage;
	private NharuOtherName[] subjectAltName;
	private String[] cdp;
	private boolean basicConstraints;
	private byte[] ski;

	/*
	 * Fields and extension not supported (yet)
	 */
	private byte[] issuerUniqueID;
	private byte[] subjectUniqueID;
	private byte[] certificatePolicies;
	private byte[] policyMappings;
	private byte[] issuerAltName;
	private byte[] subjectDirectoryAttributes;
	private byte[] nameConstraints;
	private byte[] policyConstraints;
	private int[][] extKeyUsage;
	private byte[][] inhibitAnyPolicy;
	private String[] freshestCRL;
	private String[] authorityInfoAccess;
	private String[] subjectInfoAccess;

	/**
	 * Creates a new insatance from CertificateParams from a JSON document
	 * @param params: <p>JSON object that conforms the following specification:</p>
	 * <pre>
   	 *{
   	 *   "definitions": {},
   	 *   "$schema": "http://json-schema.org/draft-07/schema#",
   	 *   "$id": "http://nharu.crypthing.org/cert-profile.json",
   	 *   "type": "object",
   	 *   "title": "Certificate Profile",
   	 *   "required": [
   	 *      "version",
   	 *      "serialNumber",
   	 *      "signature",
   	 *      "issuer",
   	 *      "validity",
   	 *      "subject",
   	 *      "subjectPublicKeyInfo",
   	 *      "extensions"
   	 *   ],
   	 *   "properties": {
   	 *      "version": {
   	 *         "$id": "#/properties/version",
   	 *         "type": "integer",
   	 *         "title": "Certificate version",
   	 *         "description": "Version ::= INTEGER  {  v1(0), v2(1), v3(2)  }",
   	 *         "default": 0,
   	 *         "examples": [ "2" ]
   	 *      },
   	 *      "serialNumber": {
   	 *         "$id": "#/properties/serialNumber",
   	 *         "type": "hexadecimal string",
   	 *         "title": "Certificate serial number",
   	 *         "description": "CertificateSerialNumber ::= INTEGER as a hexadecimal value (little endian)",
   	 *         "default": null,
   	 *         "examples": [ "604C010304A034043231" ],
   	 *         "pattern": "^([A-F,a-f,0-9]*)$"
   	 *      },
   	 *      "signature": {
   	 *         "$id": "#/properties/signature",
   	 *         "type": "object",
   	 *         "title": "Certificate signature algorithm identifier",
   	 *         "required": [ "algorithm" ],
   	 *         "properties": {
   	 *            "algorithm": {
   	 *               "$id": "#/properties/signature/properties/algorithm",
   	 *               "type": "array of numbers",
   	 *               "title": "Algorithm identifier",
   	 *               "description": "OBJECT IDENTIFIER as an array of numbers",
   	 *               "examples": [ "[1, 2, 840, 113549, 1, 1, 11]" ]
   	 *            },
   	 *            "parameters": {
   	 *               "$id": "#/properties/signature/properties/parameters",
   	 *               "type": "any",
   	 *               "title": "Algorithm parameters"
   	 *            }
   	 *         }
   	 *      },
   	 *      "issuer": {
   	 *         "$id": "#/properties/issuer",
   	 *         "type": "array",
   	 *         "title": "Certificate issuer",
   	 *         "description": "X.500 Name",
   	 *         "items": {
   	 *            "$id": "#/properties/issuer/items",
   	 *            "type": "object",
   	 *            "title": "The Items Schema",
   	 *            "required": [ "oid", "value" ],
   	 *            "properties": {
   	 *               "oid": {
   	 *                  "$id": "#/properties/issuer/items/properties/oid",
   	 *                  "type": "array of numbers",
   	 *                  "title": "Name object identifier",
   	 *                  "description": "OBJECT IDENTIFIER as an array of number",
   	 *                  "examples": [ "[ 2, 5, 4, 6 ]" ]
   	 *               },
   	 *               "value": {
   	 *                  "$id": "#/properties/issuer/items/properties/value",
   	 *                  "type": "string",
   	 *                  "title": "Name value",
   	 *                  "examples": [ "BR" ]
   	 *               }
   	 *            }
   	 *         }
   	 *      },
   	 *      "validity": {
   	 *         "$id": "#/properties/validity",
   	 *         "type": "object",
   	 *         "title": "Certificate Validity",
   	 *         "description": "Validity ::= SEQUENCE { notBefore GeneralizedTime, notAfter GeneralizedTime }",
   	 *         "required": [ "notBefore", "notAfter" ],
   	 *         "properties": {
   	 *            "notBefore": {
   	 *               "$id": "#/properties/validity/properties/notBefore",
   	 *               "type": "string",
   	 *               "title": "Certificate validity start date and time",
   	 *               "examples": [ "20180925173943Z" ],
   	 *               "pattern": "yyyyMMddHHmmssZ"
   	 *            },
   	 *            "notAfter": {
   	 *               "$id": "#/properties/validity/properties/notAfter",
   	 *               "type": "string",
   	 *               "title": "Certificate validity end date and time",
   	 *               "examples": [ "20190925173943Z" ],
   	 *               "pattern": "yyyyMMddHHmmssZ"
   	 *            }
   	 *         }
   	 *      },
   	 *      "subject": {
   	 *         "$id": "#/properties/issuer",
   	 *         "type": "array of objects",
   	 *         "title": "Certificate subject",
   	 *         "description": "X.500 Name",
   	 *         "items": {
   	 *            "$id": "#/properties/issuer/items",
   	 *            "type": "object",
   	 *            "title": "The Items Schema",
   	 *            "required": [ "oid", "value" ],
   	 *            "properties": {
   	 *               "oid": {
   	 *                  "$id": "#/properties/issuer/items/properties/oid",
   	 *                  "type": "array of numbers",
   	 *                  "title": "Name object identifier",
   	 *                  "description": "OBJECT IDENTIFIER as an array of integer",
   	 *                  "examples": [ "[ 2, 5, 4, 6 ]" ]
   	 *               },
   	 *               "value": {
   	 *                  "$id": "#/properties/issuer/items/properties/value",
   	 *                  "type": "string",
   	 *                  "title": "Name value",
   	 *                  "examples": [ "BR" ]
   	 *               }
   	 *            }
   	 *         }
   	 *      },
   	 *      "subjectPublicKeyInfo": {
   	 *         "$id": "#/properties/subjectPublicKeyInfo",
   	 *         "type": "hexadecimal string",
   	 *         "title": "Subject Public Key",
   	 *         "description": "OCTET STRING as an hexadecimal value",
   	 *         "examples": [ "0414E2DA5C1BE7C5F8B48428C42FBF18285ECC0BBE8B" ],
   	 *         "pattern": "^([A-F,a-f,0-9]*)$"
   	 *      },
   	 *      "extensions": {
   	 *         "$id": "#/properties/extensions",
   	 *         "type": "object",
   	 *         "title": "The Extensions Schema",
   	 *         "required": [ "standard" ],
   	 *         "properties": {
   	 *            "standard": {
   	 *               "$id": "#/properties/extensions/properties/standard",
   	 *               "type": "object",
   	 *               "title": "Standard Certificate Extensions",
   	 *               "required": [
   	 *                  "authorityKeyIdentifier",
   	 *                  "keyUsage",
   	 *                  "subjectAltName",
   	 *                  "cRLDistributionPoints"
   	 *               ],
   	 *               "properties": {
   	 *                  "authorityKeyIdentifier": {
   	 *                     "$id": "#/properties/extensions/properties/standard/properties/authorityKeyIdentifier",
   	 *                     "type": "hexadecimal string",
   	 *                     "title": "Authority Key Identifier",
   	 *                     "description": "OCTET STRING as an hexadecimal value",
   	 *                     "examples": [ "30168014E3660BD409DA334C9A8FCD3642F2FC9E95A9304C" ],
   	 *                     "pattern": "^([A-F,a-f,0-9]*)$"
   	 *                  },
   	 *                  "keyUsage": {
   	 *                     "$id": "#/properties/extensions/properties/standard/properties/keyUsage",
   	 *                     "type": "hexadecimal string",
   	 *                     "title": "Key Usage",
   	 *                     "description": "KeyUsage ::= BIT STRING { digitalSignature(0), nonRepudiation(1), keyEncipherment(2), dataEncipherment(3), keyAgreement(4), keyCertSign(5), cRLSign(6), encipherOnly(7), decipherOnly(8) } as an hexadecimal number",
   	 *                     "examples": [ "05E0" ],
   	 *                     "pattern": "^([A-F,a-f,0-9]*)$"
   	 *                  },
   	 *                  "subjectAltName": {
   	 *                     "$id": "#/properties/subjectAltName",
   	 *                     "type": "array",
   	 *                     "title": "Subject Alternative Names",
   	 *                     "items": {
   	 *                        "$id": "#/properties/subjectAltName/items",
   	 *                        "type": "object",
   	 *                        "title": "Definition",
   	 *                        "required": [ "oid", "value" ],
   	 *                        "properties": {
   	 *                           "oid": {
   	 *                              "$id": "#/properties/subjectAltName/items/properties/oid",
   	 *                              "type": "array of numbers",
   	 *                              "title": "Alternative Name OID",
   	 *                              "description": "OBJECT IDENTIFIER as an array of number",
   	 *                              "examples": [ "[ 1, 3, 6, 1, 4, 1, 311, 20, 2, 3 ]" ]
   	 *                           },
   	 *                           "value": {
   	 *                              "$id": "#/properties/subjectAltName/items/properties/value",
   	 *                              "type": "string",
   	 *                              "title": "Alternative Name value",
   	 *                              "examples": [ "imyself@microsofot, com" ]
   	 *                           }
   	 *                        }
   	 *                     }
   	 *                  },
   	 *                  "subjectKeyIdentifier": {
   	 *                     "$id": "#/properties/extensions/properties/standard/properties/subjectKeyIdentifier",
   	 *                     "type": "hexadecimal string",
   	 *                     "title": "Subject Key Identifier",
   	 *                     "description": "OCTET STRING as an hexadecimal value. Required by CA certificates",
   	 *                     "examples": [ "30168014E3660BD409DA334C9A8FCD3642F2FC9E95A9304C" ],
   	 *                     "pattern": "^([A-F,a-f,0-9]*)$"
   	 *                  },
   	 *                  "basicConstraints": {
   	 *                     "$id": "#/properties/extensions/properties/standard/properties/basicConstraints",
   	 *                     "type": "boolean",
   	 *                     "title": "Basic constraints",
   	 *                     "description": "BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL }. Required by CA certificates",
   	 *                     "examples": [ "true" ]
   	 *                  },
   	 *                  "cRLDistributionPoints": {
   	 *                     "$id": "#/properties/extensions/properties/standard/properties/cRLDistributionPoints",
   	 *                     "type": "array of string",
   	 *                     "title": "CRL Distribution Points",
   	 *                     "examples": [ "[http://www.caixa.gov.br/tkn/repo, http://www.caixa.gov.br/acs]" ]
   	 *                  }
   	 *               }
   	 *            },
   	 *            "extensions": {
   	 *               "$id": "#/properties/extensions/properties/extensions",
   	 *               "type": "array",
   	 *               "title": "Non-standard extensions",
   	 *               "items": {
   	 *                  "$id": "#/properties/extensions/properties/extensions/items",
   	 *                  "type": "object",
   	 *                  "title": "Items",
   	 *                  "required": [ "extnID", "extnValue" ],
   	 *               "   properties": {
   	 *                     "extnID": {
   	 *                        "$id": "#/properties/extensions/properties/extensions/items/properties/extnID",
   	 *                        "type": "array of numbers",
   	 *                        "title": "Extensions OID",
   	 *                        "description": "OBJECT IDENTIFIER as an array of numbers",
   	 *                        "examples": [ "[1, 3, 6, 1, 5, 5, 7, 1, 1 ]" ]
   	 *                     },
   	 *                     "critical": {
   	 *                        "$id": "#/properties/extensions/properties/extensions/items/properties/critical",
   	 *                        "type": "boolean",
   	 *                        "title": "Critical indicator",
   	 *                        "default": false,
   	 *                        "examples": [ "true" ]
   	 *                     },
   	 *                     "extnValue": {
   	 *                        "$id": "#/properties/extensions/properties/extensions/items/properties/extnValue",
   	 *                        "type": "hexadecimal string",
   	 *                        "title": "Extension value OCTET STRING as an hexadecimal value",
   	 *                        "examples": [ "305B305906082B06010505073002864D687474703A2F2F7777772E72656963702E636F726564662E63616978612F7265706F7369746F72696F2F63616465696176322F6169612F6163696370746573746573737562706A76322E703762" ]
   	 *                     }
   	 *                  }
   	 *               }
   	 *            }
   	 *         }
   	 *      }
   	 *   }
   	 *}
	 * </pre>
	 */
	public CertificateParams(final String params) throws ParameterException
	{
		try
		{
			final JSONObject json = new JSONObject(params);
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
			setSubjectAltName(extensions.getJSONArray("subjectAltName").toString());

			array = extensions.getJSONArray("cRLDistributionPoints");
			final String[] param = new String[array.length()];
			for (int i = 0; i< array.length(); i++) param[i] = array.getString(i);
			setCDP(param);

			if (extensions.has("basicConstraints") && extensions.getBoolean("basicConstraints")) turnonBasicConstraints();
			if (extensions.has("subjectKeyIdentifier")) setSKI(fromHex(extensions.getString("subjectKeyIdentifier")));
		}
		catch (RuntimeException e) { throw new ParameterException(e); }
	}
	/**
	 * <p>Creates a default certificate parameters instance.
	 * The following values are default:</p>
	 * <ul>
	 * <li>version: 2 (v(3))</li>
	 * <li>signature algorithm: SHA256withRSA</li>
	 * <li>validity: 3 years from now</li>
	 * <li>key usage: Digital Signature, Non Repudiation, Key Encipherment</li>
	 * </ul>
	 */
	public CertificateParams()
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
	 * Creates a default certificate parameters instance with specified issuer
	 * <p>The following values are set:</p>
	 * <ul>
	 * <li>version: 2 (v(3))</li>
	 * <li>signature algorithm: SHA256withRSA</li>
	 * <li>validity: 3 years from now</li>
	 * <li>key usage: Digital Signature, Non Repudiation, Key Encipherment</li>
	 * <li>issuer</li>
	 * <li>authority key identifier</li>
	 * </ul>
	 * @param issuer: Certificate issuer.
	 */
	public CertificateParams(final NharuX509Certificate issuer)
	{
		this();
		setIssuer(issuer.getIssuerX500Principal().getName());
		setAKI(issuer);
	}
	/**
	 * Creates a default certificate parameters instance with specified issuer and CRL Distribution Points
	 * <p>The following values are set:</p>
	 * <ul>
	 * <li>version: 2 (v(3))</li>
	 * <li>signature algorithm: SHA256withRSA</li>
	 * <li>validity: 3 years from now</li>
	 * <li>key usage: Digital Signature, Non Repudiation, Key Encipherment</li>
	 * <li>issuer</li>
	 * <li>authority key identifier</li>
	 * <li>CLR Distribution Points</li>
	 * </ul>
	 * @param issuer: Certificate issuer.
	 * @param cdp: CLR Distribution Points URIs.
	 */
	public CertificateParams(final NharuX509Certificate issuer, final String cdp[])
	{
		this(issuer);
		setCDP(cdp);
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
	 * Gets certificate signature algorithm OID JSON representation
	 * @return: JSON fragment
	 */
	public String getSignature()
	{
		if (signatureAlgorithm == null) throw new RuntimeException("Instance field must not be null");
		final StringBuilder builder = new StringBuilder(128);
		builder.append("{ \"algorithm\": [ ");
		int i = 0;
		while (i < signatureAlgorithm.length - 1) builder.append(signatureAlgorithm[i++]).append(", ");
		builder.append(signatureAlgorithm[i]).append(" ] }");
		return builder.toString();
	}
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
	 * Gets certificate issuer JSON representation
	 * @return: JSON fragment
	 */
	public String formatIssuer() { return formatName(issuer); }
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
		SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmmss");
		df.setTimeZone(TimeZone.getTimeZone("GMT"));
		return df.format(notBefore);
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
		try
		{
			SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmmss");
			df.setTimeZone(TimeZone.getTimeZone("GMT"));
			notBefore = df.parse(date);
		}
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
		SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmmss");
		df.setTimeZone(TimeZone.getTimeZone("GMT"));
		return df.format(notAfter);
	}
	public void setNotAfter(final Date date) { if ((notAfter = date) == null) throw new NullPointerException(); }
	/**
	 * Sets validity end date
	 * @param date: the date as a GeneralizedTime
	 */
	public void setNotAfter(final String date)
	{
		try
		{
			SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmmss");
			df.setTimeZone(TimeZone.getTimeZone("GMT"));
			notAfter = df.parse(date);
		}
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
	 * Gets certificagte subject JSON representation
	 * @return: JSON fragment
	 */
	public String formatSubject() { return formatName(subject); }
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
	public NharuRSAPublicKey getPublicKey() { return publicKey; }
	/**
	 * Sets certificate public key info
	 * @param key: the public key itself
	 */
	public void setPublicKey(final NharuRSAPublicKey key) { if ((publicKey = key) == null) throw new IllegalArgumentException("Argument must not be null"); }
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

	/**
	 * Gets SubjectAltName extension value
	 * @return: extension value
	 */
	public NharuOtherName[] getSubjectAltName() { return subjectAltName; }
	/**
	 * Gets SubjectAltName extension value as a JSON fragment in form
	 * [ { "oid": [ 2, 16, 76, 1, 3, 5 ], "value": "0000000000000000000Rio de Janeiro      RJ" },
	 * { "oid": [ 2, 16, 76, 1, 3, 6 ], "value": "000000000000" } ]
	 * @return: JSON fragment
	 */
	public String formatSubjectAltName()
	{
		if (subjectAltName == null) throw new RuntimeException("Instance field must not be null");
		final StringBuilder builder = new StringBuilder(512);
		int i = 0;
		builder.append("[ ");
		while (i < subjectAltName.length - 1) builder.append(subjectAltName[i++].toString()).append(", ");
		builder.append(subjectAltName[i].toString()).append(" ]");
		return builder.toString();
	}
	/**
	 * Sets SubjectAltName extension values
	 * @param names: extension other names
	 */
	public void setSubjectAltName(final NharuOtherName[] names) { if ((subjectAltName = names) == null || subjectAltName.length == 0) throw new IllegalArgumentException("Argument must not be null"); }
	/**
	 * Sets SubjectAltName extension value from a JSON fragment
	 * @param fragment: the JSON array to parse
	 */
	public void setSubjectAltName(final String fragment)
	{
		final JSONArray ob = new JSONArray(fragment);
		subjectAltName = new NharuOtherName[ob.length()];
		for (int i = 0; i< ob.length(); i++) subjectAltName[i] = new NharuOtherName(ob.getJSONObject(i).toString());
	}

	/**
	 * Gets CRL Distribution Points extension value
	 * @return: array of URIs
	 */
	public String[] getCDP() { return cdp; }
	/**
	 * Gets CRL Distribution Points extension value as a JSON array of strings
	 * @return: JSON fragment
	 */
	public String formatCDP()
	{
		if (cdp == null) throw new RuntimeException("Instance field must not be null");
		final StringBuilder builder = new StringBuilder(512);
		builder.append("[ ");
		int i = 0;
		while (i < cdp.length - 1) builder.append("\"").append(cdp[i++]).append("\", ");
		builder.append("\"").append(cdp[i]).append("\" ]");
		return builder.toString();
	}
	/**
	 * Sets CRL Distribution Points extension value
	 * @param cdp: URIs.
	 */
	public void setCDP(final String[] cdp) { if ((this.cdp =  cdp) == null) throw new IllegalArgumentException("Argument must not be null"); }

	/**
	 * Gets BasicConstraints extension value
	 * @return: extension value
	 */
	public boolean getBasicConstraints() { return basicConstraints; }
	/**
	 * Togle BasicConstraints extension value to CA
	 */
	public void turnonBasicConstraints() { basicConstraints = true; }

	/**
	 * Gets Subject Key Identifier extension value
	 * @return: extension value
	 */
	public byte[] getSKI() { return ski; }
	/**
	 * Sets Subject Key Identifier extension value
	 * @param value: extension value
	 */
	public void setSKI(final byte[] value ) { if ((ski = value) == null) throw new IllegalArgumentException("Argument must not be null"); }
	/**
	 * Sets Subject Key Identifier extension value
	 * @param pubkey: subject Public Key to calculate SHA-1 hash.  Must be an instance of NharuRSAPublicKey
	 */
	public void setSKI(final PublicKey pubkey)
	{
		if (!(pubkey instanceof NharuRSAPublicKey)) throw new IllegalArgumentException("Unsupported Public Key type");
		ski = ((NharuRSAPublicKey)pubkey).getKeyIdentifier();
	}
	private void __checkArray(final Object[] arr) throws CertificateProfileException
	{
		if (arr == null) throw new CertificateProfileException(new NullPointerException());
		for (Object o: arr) if (o == null) throw new CertificateProfileException(new NullPointerException());
	}

	/**
	 * Checks if current state conforms specified certificate profile
	 * @param profile: required profile.
	 * @throws CertificateProfileException if state does not match profile
	 */
	public void check(final CertificateProfile profile) throws CertificateProfileException
	{
		if (version != profile.version) throw new CertificateProfileException("Version field does not match");
		if (serial == null) throw new CertificateProfileException("Serial number field does not match");
		if (Arrays.equals(signatureAlgorithm, NharuCommon.stringToOID(profile.signatureAlgorithm))) throw new CertificateProfileException("Signature algorithm field does not match");
		__checkArray(issuer);
		if (notBefore == null || notAfter == null) throw new CertificateProfileException("Validity field does not match");
		final Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
		cal.setTime(notBefore);
		cal.add(Calendar.YEAR, profile.validity);
		if (!cal.getTime().equals(notAfter)) throw new CertificateProfileException("Validity field does not match");
		__checkArray((subject));
		if (publicKey == null || !publicKey.getAlgorithm().equalsIgnoreCase(profile.publicKeyAlgorithm)) throw new CertificateProfileException("Public Key Info field does not match");
		if (profile.issuerUniqueID && issuerUniqueID == null) throw new CertificateProfileException("Issuer Unique ID field does not match");
		if (profile.subjectUniqueID && subjectUniqueID == null) throw new CertificateProfileException("Subject Unique ID field does not match");
		if (profile.authorityKeyIdentifier && aki == null) throw new CertificateProfileException("Authority Key Identifier extension does not match");
		if (profile.subjectKeyIdentifier && ski == null)  throw new CertificateProfileException("Subject Key Identifier extension does not match");
		if (profile.keyUsage && keyUsage == null) throw new CertificateProfileException("Key Usage extension does not match");
		if (profile.certificatePolicies && certificatePolicies == null) throw new CertificateProfileException("Certificatge Policies extension does not match");
		if (profile.policyMappings && policyMappings == null) throw new CertificateProfileException("Policy Mappings extension does not match");
		if (profile.subjectAltName) __checkArray(subjectAltName);
		if (profile.issuerAltName && issuerAltName == null) throw new CertificateProfileException("Issuer Alternative Name extension does not match");
		if (profile.subjectDirectoryAttributes && subjectDirectoryAttributes == null) throw new CertificateProfileException("Subject Directory Attributes extension does not match");
		if (profile.basicConstraints != basicConstraints) throw new CertificateProfileException("Basic Constraints extension does not match");
		if (profile.nameConstraints && nameConstraints == null) throw new CertificateProfileException("Name Constraints extension does not match");
		if (profile.policyConstraints && policyConstraints == null) throw new CertificateProfileException("Policy Constraints extension does not match");
		if (profile.extKeyUsage && extKeyUsage == null) throw new CertificateProfileException("Extended Key Usage extension does not match");
		if (profile.cRLDistributionPoints)__checkArray(cdp);
		if (profile.inhibitAnyPolicy && inhibitAnyPolicy== null) throw new CertificateProfileException("Inhibit Any Policy extension does not match");
		if (profile.freshestCRL)__checkArray(freshestCRL);
		if (profile.authorityInfoAccess) __checkArray(authorityInfoAccess);
		if (profile.subjectInfoAccess ) __checkArray(subjectInfoAccess);
	}

	@Override
	public String toString()
	{
		final StringBuilder builder = new StringBuilder(4096);
		builder
			.append("{ \"version\": ").append(getVersion()).append(", ")
			.append("\"serialNumber\": \"").append(toHex(serial.toByteArray())).append("\", ")
			.append("\"signature\": ").append(getSignature()).append(", ")
			.append("\"issuer\": ").append(formatIssuer()).append(", ")
			.append("\"validity\": ").append(getValidity()).append(", ")
			.append("\"subject\": ").append(formatSubject()).append(", ")
			.append("\"subjectPublicKeyInfo\": \"").append(toHex(getPublicKey().getEncoded())).append("\", ")
			.append("\"extensions\": { \"standard\": { \"authorityKeyIdentifier\": \"").append(toHex(getAKI())).append("\", ")
			.append("\"keyUsage\": \"").append(toHex(getKeyUsage())).append("\", ")
			.append("\"subjectAltName\": ").append(formatSubjectAltName()).append(", ")
			.append("\"cRLDistributionPoints\": ").append(formatCDP());
		if (ski != null) builder.append(", \"subjectKeyIdentifier\": \"").append(toHex(ski)).append(" \"");
		if (basicConstraints) builder.append(",  \"basicConstraints\": ").append(basicConstraints);
		builder.append(" }}}");
		return builder.toString();
	}
	@Override
	public Object clone()
	{
		final CertificateParams ret = new CertificateParams();
		ret.version = version;
		if (serial != null) ret.serial = new BigInteger(serial.toByteArray());
		if (signatureAlgorithm != null) ret.signatureAlgorithm = Arrays.copyOf(signatureAlgorithm, signatureAlgorithm.length);
		if (issuer != null)
		{
			ret.issuer = new NharuX500Name[issuer.length];
			for (int i = 0; i < issuer.length; i++) ret.issuer[i] = (NharuX500Name) issuer[i].clone();
		}
		if (notBefore != null) ret.notBefore = new Date(notBefore.getTime());
		if (notAfter != null) ret.notAfter = new Date(notAfter.getTime());
		if (subject != null)
		{
			ret.subject = new NharuX500Name[subject.length];
			for (int i = 0; i < subject.length; i++) ret.subject[i] = (NharuX500Name) subject[i].clone();
		}
		try { if (publicKey != null) ret.publicKey = new NharuRSAPublicKey(publicKey.getEncoded()); }
		catch (EncodingException e) { throw new RuntimeException(e); }
		if (aki != null) ret.aki = Arrays.copyOf(aki, aki.length);
		if (keyUsage != null) ret.keyUsage = Arrays.copyOf(keyUsage, keyUsage.length);
		if (subjectAltName != null)
		{
			ret.subjectAltName = new NharuOtherName[subjectAltName.length];
			for (int i = 0; i < subjectAltName.length; i++) ret.subjectAltName[i] = (NharuOtherName) subjectAltName[i].clone();
		}
		if (cdp != null)
		{
			ret.cdp = new String[cdp.length];
			for (int i = 0; i < cdp.length; i++) ret.cdp[i] = new String(cdp[i]);
		}
		ret.basicConstraints = basicConstraints;
		if (ski != null) ret.ski = Arrays.copyOf(ski, ski.length);
		if (issuerUniqueID != null) ret.issuerUniqueID = Arrays.copyOf(issuerUniqueID, issuerUniqueID.length);
		if (subjectUniqueID != null) ret.subjectUniqueID = Arrays.copyOf(subjectUniqueID, subjectUniqueID.length);
		if (certificatePolicies != null) ret.certificatePolicies = Arrays.copyOf(certificatePolicies, certificatePolicies.length);
		if (policyMappings != null) ret.policyMappings = Arrays.copyOf(policyMappings, policyMappings.length);
		if (issuerAltName != null) ret.issuerAltName = Arrays.copyOf(issuerAltName, issuerAltName.length);
		if (subjectDirectoryAttributes != null) ret.subjectDirectoryAttributes = Arrays.copyOf(subjectDirectoryAttributes, subjectDirectoryAttributes.length);
		if (nameConstraints != null) ret.nameConstraints = Arrays.copyOf(nameConstraints, nameConstraints.length);
		if (policyConstraints != null) ret.policyConstraints = Arrays.copyOf(policyConstraints, policyConstraints.length);
		if (extKeyUsage != null)
		{
			ret.extKeyUsage = new int[extKeyUsage.length][];
			for (int i = 0; i < extKeyUsage.length; i++) ret.extKeyUsage[i] = Arrays.copyOf(extKeyUsage[i], extKeyUsage[i].length);
		}
		if (inhibitAnyPolicy != null)
		{
			ret.inhibitAnyPolicy = new byte[inhibitAnyPolicy.length][];
			for (int i = 0; i < inhibitAnyPolicy.length; i++) ret.inhibitAnyPolicy[i] = Arrays.copyOf(inhibitAnyPolicy[i], inhibitAnyPolicy[i].length);
		}
		if (freshestCRL != null)
		{
			ret.freshestCRL = new String[freshestCRL.length];
			for (int i = 0; i < freshestCRL.length; i++) ret.freshestCRL[i] = new String(freshestCRL[i]);
		}
		if (authorityInfoAccess != null)
		{
			ret.authorityInfoAccess = new String[authorityInfoAccess.length];
			for (int i = 0; i < authorityInfoAccess.length; i++) ret.authorityInfoAccess[i] = new String(authorityInfoAccess[i]);
		}
		if (subjectInfoAccess != null)
		{
			ret.subjectInfoAccess = new String[subjectInfoAccess.length];
			for (int i = 0; i < subjectInfoAccess.length; i++) ret.subjectInfoAccess[i] = new String(subjectInfoAccess[i]);
		}

		return ret;
	}


	private String toHex(final byte[] bin)
	{
		if (bin == null || bin.length == 0) throw new IllegalArgumentException("Argument must not be null");
		final StringBuilder sb = new StringBuilder(4096);
		for (final byte b : bin) sb.append(String.format("%02X", b));
		return sb.toString();
	}
	private byte[] fromHex(final String hex)
	{
		if (hex == null || hex.length() % 2 != 0) throw new NumberFormatException();
		final byte[] out = new byte[hex.length() / 2];
		for (int i = 0; i < hex.length(); i += 2) out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
		return out;
	}
	static NharuX500Name[] parseName(final String name)
	{
		if (name == null) throw new NullPointerException();
		final String[] parts = name.split(",");
		final NharuX500Name[] names = new NharuX500Name[parts.length];
		for (int i = 0; i < parts.length; i++) names[i] = new NharuX500Name(parts[i]);
		return names;
	}
	private String formatName(NharuX500Name[] name)
	{
		if (name == null) throw new RuntimeException("Instance field must not be null");
		final StringBuilder builder = new StringBuilder(512);
		builder.append("[ ");
		int i = 0;
		while (i < name.length - 1) builder.append(name[i++].toJSON()).append(", ");
		builder.append(name[i].toJSON()).append(" ]");
		return builder.toString();
	}



	private static final String PARAMS =
		"{ \"version\": 2, " +
		"\"serialNumber\": \"22DE\", " +
		"\"signature\": { \"algorithm\": [ 1, 2, 840, 113549, 1, 1, 11 ] }, " +
		"\"issuer\": [ { \"oid\": [ 2, 5, 4, 3 ], \"value\": \"Common Name for All Cats End User CA\" }, " +
		"{ \"oid\": [ 2, 5, 4, 11 ], \"value\": \"PKI Ruler for All Cats\" }, " +
		"{ \"oid\": [ 2, 5, 4, 10 ], \"value\": \"PKI Brazil\" }, " +
		"{ \"oid\": [ 2, 5, 4, 6 ], \"value\": \"BR\" } ], " +
		"\"validity\": { \"notBefore\": \"20190425173943Z\", \"notAfter\": \"20220425173943Z\" }, " +
		"\"subject\": [{ \"oid\": [ 2, 5, 4, 3 ], \"value\": \"Francisvaldo Genevaldo das Torres 1554922163309\" } ], " +
		"\"subjectPublicKeyInfo\": \"30820122300D06092A864886F70D01010105000382010F003082010A0282010100B7928BD8CD77997DF19D534FB1DBC65022D9ABD7B040A30C05D5CBBB697DA4C3DA92F1A98C06145A2EF61F4BAD709EA284E760BE83DAE00AC03CE532E9F15DB9CCBC4CA217AB8913E8168832D58FE2A362E72B1B0A12947A3AE82D8C61CEC28F42EC5820A89EE9EC8466CFD38994BBC1EBF06E27C9E9F87D9D5D53C1DA18055B7EE4BB7849ACBE57C911452332F62B7DED8BDDE182DFDCE693C856020C2F8B5563992787E4E7902AAA42EECACDCDD275799437EAF741EFF090C30A5F536730E528721648D7334992DE74C805F331360155A663522E0E12FD31BE2670133A687D5780F4A6843F0010B4092DCFC6DC6D7960A9555B1D6B4C92433090428059607D0203010001\", " +
		"\"extensions\": { \"standard\": { " +
		"\"authorityKeyIdentifier\": \"7626E65E348A19A34B136EA5001BBBED4BB43D55\", " +
		"\"keyUsage\": \"05E0\", " +
		"\"subjectAltName\": [ { \"oid\": [ 1, 3, 6, 1, 4, 1, 311, 20, 2, 3 ], \"value\": \"imyself@microsofot.com\" }, " +
		"{ \"oid\": [ 2, 16, 76, 1, 3, 1 ], \"value\": \"000000000000000000000000000000000000000000000DETRANRJ\" }, " +
		"{ \"oid\": [ 2, 16, 76, 1, 3, 5 ], \"value\": \"0000000000000000000Rio de Janeiro      RJ\" }, " +
		"{ \"oid\": [ 2, 16, 76, 1, 3, 6 ], \"value\": \"000000000000\" }], " +
		"\"cRLDistributionPoints\": [ \"http://www.caixa.gov.br/tkn/repo\" ]}}}";
	public static void main(String[] args)
	{
		System.out.println("CertificateParams basic tests.");
		try
		{
			CertificateParams json = new CertificateParams(PARAMS);
			System.out.print("Validating CertificateParams JSON parsing... ");
			json.check(new UserProfile());
			json = new CertificateParams(json.toString());
			System.out.println("Done!");
			
			System.out.print("Validating CertificateParams JSON  of subject... ");
			NharuCertificateRequest request = NharuCertificateRequest.parse(NharuCertificateRequest.CERTIFICATE_REQUEST.getBytes());
			String[] names = request.getSubject().getName().split(",");
			NharuX500Name[] subject = new NharuX500Name[names.length];
			for (int i = 0; i < names.length; i++) subject[i] = new NharuX500Name(names[i]);
			NharuX500Name[] jSubject = json.getSubject();
			if (jSubject.length != subject.length) throw new RuntimeException("Subject validation failure");
			for (int i = 0; i < jSubject.length; i++) if (!jSubject[i].equals(subject[i])) throw new RuntimeException("Subject validation failure");
			System.out.println("Done!");

			System.out.print("Validating CertificateParams JSON for subject public key... ");
			if (!request.getPublicKey().equals(json.getPublicKey())) throw new RuntimeException("Subject public key validation failure");
			System.out.println("Done!");

			System.out.print("Validating CertificateParams JSON for issuer... ");
			NharuX509Certificate caCert = new NharuX509Certificate(NharuCertificateEncoder.CA_CERT.getBytes());
			if (!Arrays.equals(json.getAKI(), ((NharuRSAPublicKey)caCert.getPublicKey()).getKeyIdentifier())) throw new RuntimeException("Issuer validation failure");
			names = caCert.getSubjectX500Principal().getName().split(",");
			NharuX500Name[] issuer = new NharuX500Name[names.length];
			for (int i = 0; i < names.length; i++) issuer[i] = new NharuX500Name(names[i]);
			NharuX500Name[] jIssuer = json.getIssuer();
			if (jIssuer.length != issuer.length) throw new RuntimeException("Issuer validation failure");
			for (int i = 0; i < jIssuer.length; i++) if (!jIssuer[i].equals(issuer[i])) throw new RuntimeException("Issuer validation failure");
			System.out.println("Done!");

			System.out.print("Validating CertificateParams JSON for Subject Alternative Name... ");
			NharuOtherName[] subjectAltName = json.getSubjectAltName();
			if
			(
				!subjectAltName[0].equals(new MicrosoftUPN("imyself@microsofot.com")) ||
				!subjectAltName[1].equals(new SubjectID("000000000000000000000000000000000000000000000DETRANRJ")) ||
				!subjectAltName[2].equals(new SubjectTE("0000000000000000000Rio de Janeiro      RJ")) ||
				!subjectAltName[3].equals(new SubjectCEI("000000000000"))
			)	throw new RuntimeException("Subject Alternative Name validation failure");
			System.out.println("Done!");
			System.out.println("CertificateParams basic tests done!");
		}
		catch (Exception e) { e.printStackTrace(); }
	}
}
