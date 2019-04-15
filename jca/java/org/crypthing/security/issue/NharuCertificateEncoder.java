package org.crypthing.security.issue;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;

import org.crypthing.security.EncodingException;
import org.crypthing.security.SignerInterface;
import org.crypthing.security.provider.NharuProvider;

/**
 * <p>
 * X.509 Certificate encoder.<br>
 * See RFC 5280.<br>
 * </p>
 * <p>
 * Following fragment shows how to sign a certificate:
 * </p>
 * <p>
 * 1. Receive PKCS#10 request and parse it using NharuCertificateRequest.
 * </p>
 * <p>
 * 2. Verify PKCS#10 signature and extracts its subjectPublicKeyInfo.
 * </p>
 * <p>
 * 3. Collect subject data according to CA profile and creates a JSON document as follows:
 * </p>
 * <pre>
 *  {
 *  	"version": 2,
 *  	"serialNumber": "604C010304A034043231",
 *  	"signature": { "algorithm": [ 1, 2, 840, 113549, 1, 1, 11 ] },
 *  	"issuer": [
 *  		{ "oid": [ 2, 5, 4, 6 ], "value": "BR" },
 *  		{ "oid": [ 2, 5, 4, 10 ], "value": "ICP-Icptestes" },
 *  		{ "oid": [ 2, 5, 4, 11 ], "value": "AC Icptestes Sub v2" },
 *  		{ "oid": [ 2, 5, 4, 3 ], "value": "AC Icptestes Sub PJ v2" }
 *  	],
 *  	"validity": {
 *  		"notBefore": "20180925173943Z",
 *  		"notAfter": "20190925173943Z"
 *  	},
 *  	"subject": [
 *  		{ "oid": [ 2, 5, 4, 3 ], "value": "FRANCISVALDO ALVES DA SILVA:10986785830" }
 *  	],
 *  	"subjectPublicKeyInfo": {
 *  		"algorithm": { "algorithm": [ 1, 2, 840, 113549, 1, 1, 1 ] },
 *  		"subjectPublicKey": "5303030313034A0260605604C010302A01D041B4652414E43495356414C444F20414C5645532044412053494C5641"
 *  	},
 *  	"extensions": {
 *  		"standard": {
 *  			"authorityKeyIdentifier": "30168014E3660BD409DA334C9A8FCD3642F2FC9E95A9304C",
 *  			"subjectKeyIdentifier": "0414E2DA5C1BE7C5F8B48428C42FBF18285ECC0BBE8B",
 *  			"keyUsage": "030205E0",
 *  			"subjectAltName": [
 *  				{ "type": "otherName", "oid": [ 1, 3, 6, 1, 4, 1, 311, 20, 2, 3 ], "value": "imyself@microsofot, com" },
 *  				{ "type": "otherName", "oid": [ 2, 16, 76, 1, 3, 1 ], "value": "000000000000000000000000000000000000000000000DETRANRJ" },
 *  				{ "type": "otherName", "oid": [ 2, 16, 76, 1, 3, 5 ], "value": "0000000000000000000Rio de Janeiro      RJ" },
 *  				{ "type": "otherName", "oid": [ 2, 16, 76, 1, 3, 6 ], "value": "000000000000" }
 *  			],
 *  			"basicConstraints": true,
 *  			"extKeyUsage":   [[ 1, 3, 6, 1, 5, 5, 7, 3, 2 ], [ 1, 3, 6, 1, 5, 5, 7, 3, 4 ]],
 *  			"cRLDistributionPoints": [ "http://www.caixa.gov.br/tkn/repo" ]
 *  		},
 *  		"extensions": [
 *  			{
 *  				"extnID": [ 1, 3, 6, 1, 5, 5, 7, 1, 1 ],
 *  				"critical": false,
 *  				"extnValue": "305B305906082B06010505073002864D687474703A2F2F7777772E72656963702E636F726564662E63616978612F7265706F7369746F72696F2F63616465696176322F6169612F6163696370746573746573737562706A76322E703762"
 *  			}
 *  		]
 *  	}
 *  }
 * </pre>
 * <p>
 * 4. Collect CA private key (or a reference to it) from any security vault and passe it to a 
 * java.security.interfaces.RSAPrivateKey and org.crypthing.security.SignerInterface implementation.
 * For a JKS/PKCS#12 storage, you may use org.crypthing.security.NharuRSAPrivateKey.
 * </p>
 * <p>
 * 5. Call sign() and, if successfull, then encode(). For example:
 * </p>
 * <pre>
 * 
 *  byte[] encoding = ...                                   // Collect CA private key RSA DER encoding
 *  NharuX509Certificate[] chain = ...                      // Collect CA chain
 *  try
 *  {
 *  	NharuRSAPrivateKey pKey = new NharuRSAPrivateKey(encoding);
 *  	try
 *  	{
 *  		byte[] certRequest = ...                        // Collect PKCS#10 request
 *  		NharuCertificateRequest request = NharuCertificateRequest.parse(certRequest);
 *  		try
 *  		{
 *  			request.verify();                         // Verify PKCS#10 signature
 *  			request.getSubject();                     // Locate user and collect its data
 *  			request.getPublicKey();                   // Extract PKCS#10 public key to certificate
 *  			String json = ...                         // Collect subject data according to certificate profile
 *  			NharuCertificateEncoder encoder = new NharuCertificateEncoder(json);
 *  			try
 *  			{
 *  				encoder.sign("SHA256withRSA", pKey);// Sign certificate with CA key
 *  				NharuX509Certificate cert = new NharuX509Certificate(encoder.encode());
 *  				CMSSignedDataBuilder cms = new CMSSignedDataBuilder();
 *  				cms.addCertificate(cert);           // Add user certificate
 *  				cms.addCertificates(chain);         // Add CA chain
 *  				byte[] pkcs7 = cms.encode();        // Encode CMS Signed Data and bon voyage
 *  			}
 *  			finally { encoder.releaseObject(); }
 *  		}
 *  		finally { request.releaseObject(); }
 *  	}
 *  	finally { pKey.releaseObject(); }
 *  } 
 *  catch (InvalidKeyException e)         { * Thrown if CA private key could not be retrieved * }
 *  catch (EncodingException e)           { * Thrown if PKCS#10 request or generated Certifiate is malformed * }
 *  catch (SignatureException e)          { * Thrown if PKCS#10 signature could not be verified * }
 *  catch (CertificateProfileException e) { * Thrown if certificate profile is inconsistent * }
 *  catch (GeneralSecurityException e)    { * Thrown if certificate could not be signed * }
 * 
 * </pre>
 * 
 * 
 */
public class NharuCertificateEncoder
{

	static { NharuProvider.isLoaded(); }
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws NotSerializableException { throw new NotSerializableException(); }


	/**
	 * Creates a new encoder to issue a X.509 Certificate.
	 * 
	 * @param profile: Certificate profile. Must conforms following JSON schema:
	 * 
	 *                 <pre>
	 *  {
	 *  	"definitions": {},
	 *  	"$schema": "http://json-schema.org/draft-07/schema#",
	 *  	"$id": "http://nharu.crypthing.org/cert-profile.json",
	 *  	"type": "object",
	 *  	"title": "Certificate Profile",
	 *  	"required": [
	 *  		"version",
	 *  		"serialNumber",
	 *  		"signature",
	 *  		"issuer",
	 *  		"validity",
	 *  		"subject",
	 *  		"subjectPublicKeyInfo",
	 *  		"extensions"
	 *  	],
	 *  	"properties": {
	 *  		"version": {
	 *  			"$id": "#/properties/version",
	 *  			"type": "integer",
	 *  			"title": "Certificate version",
	 *  			"description": "Version ::= INTEGER  {  v1(0), v2(1), v3(2)  }",
	 *  			"default": 0,
	 *  			"examples": [ "2" ]
	 *  		},
	 *  		"serialNumber": {
	 *  			"$id": "#/properties/serialNumber",
	 *  			"type": "hexadecimal string",
	 *  			"title": "Certificate serial number",
	 *  			"description": "CertificateSerialNumber ::= INTEGER as a hexadecimal value",
	 *  			"default": null,
	 *  			"examples": [ "604C010304A034043231" ],
	 *  			"pattern": "^([A-F,a-f,0-9]*)$"
	 *  		},
	 *  		"signature": {
	 *  			"$id": "#/properties/signature",
	 *  			"type": "object",
	 *  			"title": "Certificate signature algorithm identifier",
	 *  			"description": "CertificateSerialNumber ::= INTEGER",
	 *  			"required": [ "algorithm" ],
	 *  			"properties": {
	 *  				"algorithm": {
	 *  					"$id": "#/properties/signature/properties/algorithm",
	 *  					"type": "array of numbers",
	 *  					"title": "Algorithm identifier",
	 *  					"description": "OBJECT IDENTIFIER as an array of numbers",
	 *  					"examples": [ "[1, 2, 840, 113549, 1, 1, 11]" ]
	 *  				},
	 *  				"parameters": {
	 *  					"$id": "#/properties/signature/properties/parameters",
	 *  					"type": "any",
	 *  					"title": "Algorithm parameters"
	 *  				}
	 *  			}
	 *  		},
	 *  		"issuer": {
	 *  			"$id": "#/properties/issuer",
	 *  			"type": "array",
	 *  			"title": "Certificate issuer",
	 *  			"description": "X.500 Name",
	 *  			"items": {
	 *  				"$id": "#/properties/issuer/items",
	 *  				"type": "object",
	 *  				"title": "The Items Schema",
	 *  				"required": [ "oid", "value" ],
	 *  				"properties": {
	 *  					"oid": {
	 *  						"$id": "#/properties/issuer/items/properties/oid",
	 *  						"type": "array of numbers",
	 *  						"title": "Name object identifier",
	 *  						"description": "OBJECT IDENTIFIER as an array of number",
	 *  						"examples": [ "[ 2, 5, 4, 6 ]" ]
	 *  					},
	 *  					"value": {
	 *  						"$id": "#/properties/issuer/items/properties/value",
	 *  						"type": "string",
	 *  						"title": "Name value",
	 *  						"examples": [ "BR" ]
	 *  					}
	 *  				}
	 *  			}
	 *  		},
	 *  		"validity": {
	 *  			"$id": "#/properties/validity",
	 *  			"type": "object",
	 *  			"title": "Certificate Validity",
	 *  			"description": "Validity ::= SEQUENCE { notBefore GeneralizedTime, notAfter GeneralizedTime }",
	 *  			"required": [ "notBefore", "notAfter" ],
	 *  			"properties": {
	 *  				"notBefore": {
	 *  					"$id": "#/properties/validity/properties/notBefore",
	 *  					"type": "string",
	 *  					"title": "Certificate validity start date and time",
	 *  					"examples": [ "20180925173943Z" ],
	 *  					"pattern": "YYYYMMDDHHSSZ"
	 *  				},
	 *  				"notAfter": {
	 *  					"$id": "#/properties/validity/properties/notAfter",
	 *  					"type": "string",
	 *  					"title": "Certificate validity start date and time",
	 *  					"examples": [ "20190925173943Z" ],
	 *  					"pattern": "YYYYMMDDHHSSZ"
	 *  				}
	 *  			}
	 *  		},
	 *  		"subject": {
	 *  			"$id": "#/properties/issuer",
	 *  			"type": "array of objects",
	 *  			"title": "Certificate subject",
	 *  			"description": "X.500 Name",
	 *  			"items": {
	 *  				"$id": "#/properties/issuer/items",
	 *  				"type": "object",
	 *  				"title": "The Items Schema",
	 *  				"required": [ "oid", "value" ],
	 *  				"properties": {
	 *  					"oid": {
	 *  						"$id": "#/properties/issuer/items/properties/oid",
	 *  						"type": "array of numbers",
	 *  						"title": "Name object identifier",
	 *  						"description": "OBJECT IDENTIFIER as an array of integer",
	 *  						"examples": [ "[ 2, 5, 4, 6 ]" ]
	 *  					},
	 *  					"value": {
	 *  						"$id": "#/properties/issuer/items/properties/value",
	 *  						"type": "string",
	 *  						"title": "Name value",
	 *  						"examples": [ "BR" ]
	 *  					}
	 *  				}
	 *  			}
	 *  		},
	 *  		"subjectPublicKeyInfo": {
	 *  			"$id": "#/properties/subjectPublicKeyInfo",
	 *  			"type": "object",
	 *  			"title": "Subject Public Key",
	 *  			"description": "SubjectPublicKeyInfo ::=  SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }",
	 *  			"required": [ "algorithm", "subjectPublicKey" ],
	 *  			"properties": {
	 *  				"algorithm": {
	 *  					"$id": "#/properties/subjectPublicKeyInfo/properties/algorithm",
	 *  					"type": "object",
	 *  					"title": "Public key algorithm",
	 *  					"required": [ "algorithm" ],
	 *  					"properties": {
	 *  						"algorithm": {
	 *  							"$id": "#/properties/subjectPublicKeyInfo/properties/algorithm/properties/algorithm",
	 *  							"type": "array of numbers",
	 *  							"title": "Algorithm identifier",
	 *  							"description": "OBJECT IDENTIFIER as an array of number",
	 *  							"examples": [ "[ 1, 2, 840, 113549, 1, 1, 1 ]" ],
	 *  						},
	 *  						"parameters": {
	 *  							"$id": "#/properties/subjectPublicKeyInfo/properties/algorithm/properties/parameters",
	 *  							"type": "any",
	 *  							"title": "Algorithm parameters"
	 *  						}
	 *  					}
	 *  				},
	 *  				"subjectPublicKey": {
	 *  					"$id": "#/properties/subjectPublicKeyInfo/properties/subjectPublicKey",
	 *  					"type": "hexadecimal string",
	 *  					"title": "Public Key",
	 *  					"description": "BIT STRING as an hexadecimal value",
	 *  					"examples": [ "5303030313034A0260605604C010302A01D041B4652414E43495356414C444F20414C5645532044412053494C5641" ],
	 *  					"pattern": "^([A-F,a-f,0-9]*)$"
	 *  				}
	 *  			}
	 *  		},
	 *  		"extensions": {
	 *  			"$id": "#/properties/extensions",
	 *  			"type": "object",
	 *  			"title": "The Extensions Schema",
	 *  			"required": [ "standard" ],
	 *  			"properties": {
	 *  				"standard": {
	 *  					"$id": "#/properties/extensions/properties/standard",
	 *  					"type": "object",
	 *  					"title": "Standard Certificate Extensions",
	 *  					"required": [
	 *  						"authorityKeyIdentifier",
	 *  						"keyUsage",
	 *  						"subjectAltName",
	 *  						"basicConstraints",
	 *  						"extKeyUsage",
	 *  						"cRLDistributionPoints"
	 *  					],
	 *  					"properties": {
	 *  						"authorityKeyIdentifier": {
	 *  							"$id": "#/properties/extensions/properties/standard/properties/authorityKeyIdentifier",
	 *  							"type": "hexadecimal string",
	 *  							"title": "Authority Key Identifier",
	 *  							"description": "OCTET STRING as an hexadecimal value",
	 *  							"examples": [ "30168014E3660BD409DA334C9A8FCD3642F2FC9E95A9304C" ],
	 *  							"pattern": "^([A-F,a-f,0-9]*)$"
	 *  						},
	 *  						"subjectKeyIdentifier": {
	 *  							"$id": "#/properties/extensions/properties/standard/properties/subjectKeyIdentifier",
	 *  							"type": "hexadecimal string",
	 *  							"title": "Subject Key Identifier",
	 *  							"description": "OCTET STRING as an hexadecimal value",
	 *  							"examples": [ "0414E2DA5C1BE7C5F8B48428C42FBF18285ECC0BBE8B" ],
	 *  							"pattern": "^([A-F,a-f,0-9]*)$"
	 *  						},
	 *  						CertificateProfileException"keyUsage": {
	 *  						CertificateProfileException	"$id": "#/properties/extensions/properties/standard/properties/keyUsage",
	 *  						CertificateProfileException	"type": "hexadecimal string",
	 *  						CertificateProfileException	"title": "Key Usage",
	 *  						CertificateProfileException	"description": "KeyUsage ::= BIT STRING { digitalSignature(0), nonRepudiation(1), keyEncipherment(2), dataEncipherment(3), keyAgreement(4), keyCertSign(5), cRLSign(6), encipherOnly(7), decipherOnly(8) } as an hexadecimal number",
	 *  						CertificateProfileException	"examples": [ "030205E0" ],
	 *  							"pattern": "^([A-F,a-f,0-9]*)$"
	 *  						},
	 *  						"subjectAltName": {
	 *  							"$id": "#/properties/subjectAltName",
	 *  							"type": "array",
	 *  							"title": "Subject Alternative Names",
	 *  							"items": {
	 *  								"$id": "#/properties/subjectAltName/items",
	 *  								"type": "object",
	 *  								"title": "Definition",
	 *  								"required": [ "type", "value" ],
	 *  								"properties": {
	 *  						CertificateProfileException			"type": {
	 *  						CertificateProfileException				"$id": "#/properties/subjectAltName/items/properties/type",
	 *  						CertificateProfileException				"type": "string",
	 *  						CertificateProfileException				"enum": [ "otherName", "rfc822Name", "dNSName", "x400Address", "directoryName", "ediPartyName", "uniformResourceIdentifier", "iPAddress", "registeredID" ],
	 *  						CertificateProfileException				"title": "Alternative name type",
	 *  						CertificateProfileException				"examples": [ "otherName" ]
	 *  						CertificateProfileException			},
	 *  									"oid": {
	 *  										"$id": "#/properties/subjectAltName/items/properties/oid",
	 *  										"type": "array of numbers",
	 *  										"title": "Alternative Name OID",
	 *  										"description": "OBJECT IDENTIFIER as an array of number",
	 *  										"examples": [ "[ 1, 3, 6, 1, 4, 1, 311, 20, 2, 3 ]" ]
	 *  									},
	 *  									"value": {
	 *  										"$id": "#/properties/subjectAltName/items/properties/value",
	 *  										"type": "string",
	 *  										"title": "Alternative Name value",
	 *  										"examples": [ "imyself@microsofot, com" ]
	 *  									}
	 *  								}
	 *  							}
	 *  						},
	 *  						"basicConstraints": {
	 *  						CertificateProfileException	"$id": "#/properties/extensions/properties/standard/properties/basicConstraints",
	 *  							"type": "boolean",
	 *  							"title": "Basic constraints",
	 *  							"description": "BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL }",
	 *  							"examples": [ "true" ]
	 *  						},
	 *  						"extKeyUsage": {
	 *  							"$id": "#/properties/extensions/properties/standard/properties/extKeyUsage",
	 *  							"type": "array of arrays of numbers",
	 *  							"title": "Extended Key Usage",
	 *  							"description": "ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF OBJECT IDENTIFIER as an array of arrays of number",
	 *  							"examples": [ "[[ 1, 3, 6, 1, 5, 5, 7, 3, 2], [1, 3, 6, 1, 5, 5, 7, 3, 4]]" ]
	 *  						},
	 *  						"cRLDistributionPoints": {
	 *  							"$id": "#/properties/extensions/properties/standard/properties/cRLDistributionPoints",
	 *  							"type": "array of string",
	 *  							"title": "CRL Distribution Points",
	 *  							"examples": [ "[http://www.caixa.gov.br/tkn/repo, http://www.caixa.gov.br/acs]" ]
	 *  						}
	 *  					}
	 *  				},
	 *  				"extensions": {
	 *  					"$id": "#/properties/extensions/properties/extensions",
	 *  					"type": "array",
	 *  					"title": "Non-standard extensions",
	 *  					"items": {
	 *  						"$id": "#/properties/extensions/properties/extensions/items",
	 *  						"type": "object",
	 *  						"title": "Items",
	 *  						"required": [ "extnID", "extnValue" ],
	 *  					"	properties": {
	 *  							"extnID": {
	 *  								"$id": "#/properties/extensions/properties/extensions/items/properties/extnID",
	 *  								"type": "array of numbers",
	 *  								"title": "Extensions OID",
	 *  								"description": "OBJECT IDENTIFIER as an array of numbers",
	 *  								"examples": [ "[1, 3, 6, 1, 5, 5, 7, 1, 1 ]" ]
	 *  							},
	 *  							"critical": {
	 *  								"$id": "#/properties/extensions/properties/extensions/items/properties/critical",
	 *  								"type": "boolean",
	 *  								"title": "Critical indicator",
	 *  								"default": false,
	 *  								"examples": [ "true" ]
	 *  							},
	 *  							"extnValue": {
	 *  								"$id": "#/properties/extensions/properties/extensions/items/properties/extnValue",
	 *  								"type": "hexadecimal string",
	 *  								"title": "Extension value OCTET STRING as an hexadecimal value",
	 *  								"examples": [ "305B305906082B06010505073002864D687474703A2F2F7777772E72656963702E636F726564662E63616978612F7265706F7369746F72696F2F63616465696176322F6169612F6163696370746573746573737562706A76322E703762" ]
	 *  							}
	 *  						}
	 *  					}
	 *  				}
	 *  			}
	 *  		}
	 *  	}
	 *  }
	 *                 </pre>
	 * 
	 * @throws CertificateProfileException on failure.
	 * 
	 */
	public NharuCertificateEncoder(final String profile) throws CertificateProfileException
	{

	}

	/**
	 * Signs this certificate.
	 * 
	 * @param algorithm: signature algorithm. Only SHA1withRSA, SHA256withRSA,
	 *                   SHA384withRSA, SHA512withRSA and MD5withRSA are supported.
	 *                   Must conform signature field of certificate profile.
	 * @param signer:    signing callback. Must also implements
	 *                   java.security.interfaces.RSAPrivateKey.
	 * @throws GeneralSecurityException on failure.
	 */
	public void sign(final String algorithm, final SignerInterface signer) throws GeneralSecurityException
	{

	}

	/**
	 * Encodes this certificate, if signed.
	 * 
	 * @return a DER encoded X.509 Certificate.
	 * @throws EncodingException on failure.
	 */
	public byte[] encode() throws EncodingException
	{
		return null;
	}

	/**
	 * Releases this object. Must be called when object is no more needed
	 */
	public void releaseObject()
	{

	}
}