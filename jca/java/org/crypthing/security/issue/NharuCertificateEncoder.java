package org.crypthing.security.issue;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import org.crypthing.security.EncodingException;
import org.crypthing.security.NharuRSAPrivateKey;
import org.crypthing.security.NharuX500Name;
import org.crypthing.security.SignerInterface;
import org.crypthing.security.provider.NharuProvider;
import org.crypthing.security.x509.NharuPKIBRParser;
import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.util.NharuCommon;

public class NharuCertificateEncoder
{

	static { NharuProvider.isLoaded();}
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws NotSerializableException { throw new NotSerializableException(); }

	private long hHandle = 0;
	private boolean signed = false;
	private byte[] encoding = null;

	/**
	 * Creates a new instance of certificate encoder
	 * @param json:CertificateParams JSON message
	 * @param profile:profile to check
	 * @throws ParameterException on invalid parameter
	 * @throws CertificateProfileException onn profile error
	 */
	public NharuCertificateEncoder(final String json, final CertificateProfile profile)throws ParameterException, CertificateProfileException { this(new CertificateParams(json), profile); }
	/**
	 * Creates a new instance of certificate encoder
	 * 
	 * @param params: certificate parameters
	 * @param profile: profile to check
	 * @throws ParameterException on invalid parameter
	 * @throws CertificateProfileException on profile error
	 */
	public NharuCertificateEncoder(final CertificateParams params, final CertificateProfile profile) throws CertificateProfileException, ParameterException
	{
		params.check(profile);
		hHandle = nhceNewCertificateEncoder();
		nhceSetVersion(hHandle, params.getVersion());
		nhceSetSerial(hHandle, params.getSerial().toByteArray());
		nhceSetSignatureAlgorithm(hHandle, params.getSignatureAlgorithm());
		nhceSetIssuer(hHandle, params.getIssuer());
		nhceSetValidity(hHandle, params.formatNotBefore(), params.formatNotAfter());
		nhceSetSubject(hHandle, params.getSubject());
		nhceSetPubkey(hHandle, params.getPublicKey().getInternalNode());
		if (params.getAKI() != null) nhceSetAKI(hHandle, params.getAKI());
		if (params.getKeyUsage() != null) nhceSetKeyUsage(hHandle, params.getKeyUsage());
		if (params.getSubjectAltName() != null) nhceSetSubjectAltName(hHandle, params.getSubjectAltName());
		if (params.getCDP() != null) nhceSetCDP(hHandle, params.getCDP());
		if (params.getBasicConstraints()) nhceSetBasicConstraint(hHandle, params.getBasicConstraints());
		if (params.getSKI() != null) nhceSetSKI(hHandle, params.getSKI());
	}

	/**
	 * Signs this TBScertificate.
	 * 
	 * @param algorithm: signature algorithm. Only SHA1withRSA, 
	 * SHA256withRSA, SHA384withRSA, SHA512withRSA and
	 * MD5withRSA are supported. Must conform signature field of certificate profile.
	 * @param signer: signing callback. Must also implements java.security.interfaces.RSAPrivateKey.
	 * @throws GeneralSecurityException on failure.
	 */
	public void sign(final String algorithm, final SignerInterface signer) throws GeneralSecurityException
	{
		if (hHandle == 0) throw new IllegalStateException("Object already released");
		if (signed) throw new IllegalStateException("Certificate already signed");
		nhceSign(hHandle, NharuCommon.getAlgorithmConstant(algorithm), signer);
		signed = true;
	}

	/**
	 * Encodes this certificate, if signed.
	 * @return a DER encoded X.509 Certificate.
	 * @throws EncodingException on failure.
	 */
	public byte[] encode() throws EncodingException
	{
		if (encoding == null)
		{
			if (!signed) throw new IllegalStateException("Certificate not signed");
			if (hHandle == 0) throw new IllegalStateException("Object already released");
			encoding = nhceEncode(hHandle);
		}
		return encoding;
	}

	/**
	 * Releases this object. Must be called when object is no more needed
	 */
	public void releaseObject()
	{
		if (hHandle != 0) nhceReleaseCertificateEncoder(hHandle);
		hHandle = 0;
	}

	private static native long nhceNewCertificateEncoder();
	private static native void nhceReleaseCertificateEncoder(long handle);
	private static native void nhceSetVersion(long handle, int value) throws ParameterException;
	private static native void nhceSetSerial(long handle, byte[] value) throws ParameterException;
	private static native void nhceSetSignatureAlgorithm(long handle, int[] value) throws ParameterException;
	private static native void nhceSetIssuer(long handle, NharuX500Name[] value) throws ParameterException;
	private static native void nhceSetValidity(long handle, String notBefore, String notAfter) throws ParameterException;
	private static native void nhceSetSubject(long handle, NharuX500Name[] value) throws ParameterException;
	private static native void nhceSetPubkey(long handle, long value) throws ParameterException;
	private static native void nhceSetAKI(long handle, byte[] value) throws ParameterException;
	private static native void nhceSetKeyUsage(long handle, byte[] value) throws ParameterException;
	private static native void nhceSetSubjectAltName(long handle, NharuOtherName[] value) throws ParameterException;
	private static native void nhceSetCDP(long handle, String[] value) throws ParameterException;
	private static native void nhceSetBasicConstraint(long handle, boolean value) throws ParameterException;
	private static native void nhceSetSKI(long handle, byte[] value) throws ParameterException;
	private static native void nhceSign(long handle, int mechanism, SignerInterface signer) throws GeneralSecurityException;
	private static native byte[] nhceEncode(long handle) throws EncodingException;



	static final String CA_CERT =
		"-----BEGIN CERTIFICATE-----\n"
		+ "MIIEbjCCA1agAwIBAgIBADANBgkqhkiG9w0BAQsFADB2MQswCQYDVQQGEwJCUjET\n"
		+ "MBEGA1UEChMKUEtJIEJyYXppbDEfMB0GA1UECxMWUEtJIFJ1bGVyIGZvciBBbGwg\n"
		+ "Q2F0czExMC8GA1UEAxMoQ29tbW9uIE5hbWUgZm9yIEFsbCBDYXRzIEludGVybWVk\n"
		+ "aWF0ZSBDQTAgFw0xOTA0MTYyMDIyMDlaGA8yMTE5MDQxNDIwMjIwOVowcjELMAkG\n"
		+ "A1UEBhMCQlIxEzARBgNVBAoTClBLSSBCcmF6aWwxHzAdBgNVBAsTFlBLSSBSdWxl\n"
		+ "ciBmb3IgQWxsIENhdHMxLTArBgNVBAMTJENvbW1vbiBOYW1lIGZvciBBbGwgQ2F0\n"
		+ "cyBFbmQgVXNlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN+x\n"
		+ "KpKi6o5QQ3fBxEdHzgF3drtxtf9bu+365cAOyTPW+GLv5X/jzP9hRdu2jAq/HhFc\n"
		+ "pdw+dCPXBBVppLyfDPv30cgqJU00MV6glZ8t99eKo9o+OU2hmGSu+XJ5uNqzjWnX\n"
		+ "TORqqEjjuRen5wsIhQszD1L53PPboD5wiVhO6qFrh+dbwrzHfErSt+HOaWO42Oyo\n"
		+ "69dB77nWxOrW84VAcFsrINfF/qYcWGMM2rwtyHkVQMKP6CO/IuyrF8UCy0RKZn1+\n"
		+ "892gijG+2APBbxpCS0qrw9xWNWaaSGns5XahINcpHOzlSdniy6xFY+A/8zmVLCJ7\n"
		+ "2tjHA0DT30elqhRQe6ECAwEAAaOCAQcwggEDMB0GA1UdDgQWBBR2JuZeNIoZo0sT\n"
		+ "bqUAG7vtS7Q9VTCBmAYDVR0jBIGQMIGNgBQGBpoixKfA+FX+BeqGNwqNLcAX06Fy\n"
		+ "pHAwbjELMAkGA1UEBhMCQlIxEzARBgNVBAoTClBLSSBCcmF6aWwxHzAdBgNVBAsT\n"
		+ "FlBLSSBSdWxlciBmb3IgQWxsIENhdHMxKTAnBgNVBAMTIENvbW1vbiBOYW1lIGZv\n"
		+ "ciBBbGwgQ2F0cyBSb290IENBggEAMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEG\n"
		+ "MCwGA1UdHwQlMCMwIaAfoB2GG2h0dHA6Ly9sb2NhbGhvc3QvYWMvZW5kLmNybDAN\n"
		+ "BgkqhkiG9w0BAQsFAAOCAQEAkd5aPwlz+Awur21hH6W3Yk/opvQfBy+7ChuDk4n7\n"
		+ "Cl2LyVyHAAuYyOPqCsalG5exQcJMgdGrVmaFSMmzOWIpaS3uffxuvA0wRX0BPIm1\n"
		+ "aC42Wz8pxODn2go2FjsAoEywhQSBmOAL1tCOYLzaTzdY43CAhYxzLlh6Ykl+ug/S\n"
		+ "TshTApAu53e+NnC5d6pmGsEwGbyh+oYVo1zahUS9iwtb0K9nvnk3NZti7HMgxq1r\n"
		+ "HNfej9EFvlm9TfktaaQOnTEhRHPDLmb5FuGFmZkaQWkDrUU/ikT3J+vCmRCV+Fl4\n"
		+ "fASwi3itqEIwQES/JyJTTAiEToGPf7j5bWbrPy1yZNh0iA==\n" 
		+ "-----END CERTIFICATE-----";
	static final byte[] CA_KEY =
	{
		(byte) 0x30, (byte) 0x82, (byte) 0x04, (byte) 0xbd, (byte) 0x02, (byte) 0x01,
		(byte) 0x00, (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x09, (byte) 0x2a, (byte) 0x86,
		(byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x01, (byte) 0x01,
		(byte) 0x05, (byte) 0x00, (byte) 0x04, (byte) 0x82, (byte) 0x04, (byte) 0xa7, (byte) 0x30,
		(byte) 0x82, (byte) 0x04, (byte) 0xa3, (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x02,
		(byte) 0x82, (byte) 0x01, (byte) 0x01, (byte) 0x00, (byte) 0xdf, (byte) 0xb1, (byte) 0x2a,
		(byte) 0x92, (byte) 0xa2, (byte) 0xea, (byte) 0x8e, (byte) 0x50, (byte) 0x43, (byte) 0x77,
		(byte) 0xc1, (byte) 0xc4, (byte) 0x47, (byte) 0x47, (byte) 0xce, (byte) 0x01, (byte) 0x77,
		(byte) 0x76, (byte) 0xbb, (byte) 0x71, (byte) 0xb5, (byte) 0xff, (byte) 0x5b, (byte) 0xbb,
		(byte) 0xed, (byte) 0xfa, (byte) 0xe5, (byte) 0xc0, (byte) 0x0e, (byte) 0xc9, (byte) 0x33,
		(byte) 0xd6, (byte) 0xf8, (byte) 0x62, (byte) 0xef, (byte) 0xe5, (byte) 0x7f, (byte) 0xe3,
		(byte) 0xcc, (byte) 0xff, (byte) 0x61, (byte) 0x45, (byte) 0xdb, (byte) 0xb6, (byte) 0x8c,
		(byte) 0x0a, (byte) 0xbf, (byte) 0x1e, (byte) 0x11, (byte) 0x5c, (byte) 0xa5, (byte) 0xdc,
		(byte) 0x3e, (byte) 0x74, (byte) 0x23, (byte) 0xd7, (byte) 0x04, (byte) 0x15, (byte) 0x69,
		(byte) 0xa4, (byte) 0xbc, (byte) 0x9f, (byte) 0x0c, (byte) 0xfb, (byte) 0xf7, (byte) 0xd1,
		(byte) 0xc8, (byte) 0x2a, (byte) 0x25, (byte) 0x4d, (byte) 0x34, (byte) 0x31, (byte) 0x5e,
		(byte) 0xa0, (byte) 0x95, (byte) 0x9f, (byte) 0x2d, (byte) 0xf7, (byte) 0xd7, (byte) 0x8a,
		(byte) 0xa3, (byte) 0xda, (byte) 0x3e, (byte) 0x39, (byte) 0x4d, (byte) 0xa1, (byte) 0x98,
		(byte) 0x64, (byte) 0xae, (byte) 0xf9, (byte) 0x72, (byte) 0x79, (byte) 0xb8, (byte) 0xda,
		(byte) 0xb3, (byte) 0x8d, (byte) 0x69, (byte) 0xd7, (byte) 0x4c, (byte) 0xe4, (byte) 0x6a,
		(byte) 0xa8, (byte) 0x48, (byte) 0xe3, (byte) 0xb9, (byte) 0x17, (byte) 0xa7, (byte) 0xe7,
		(byte) 0x0b, (byte) 0x08, (byte) 0x85, (byte) 0x0b, (byte) 0x33, (byte) 0x0f, (byte) 0x52,
		(byte) 0xf9, (byte) 0xdc, (byte) 0xf3, (byte) 0xdb, (byte) 0xa0, (byte) 0x3e, (byte) 0x70,
		(byte) 0x89, (byte) 0x58, (byte) 0x4e, (byte) 0xea, (byte) 0xa1, (byte) 0x6b, (byte) 0x87,
		(byte) 0xe7, (byte) 0x5b, (byte) 0xc2, (byte) 0xbc, (byte) 0xc7, (byte) 0x7c, (byte) 0x4a,
		(byte) 0xd2, (byte) 0xb7, (byte) 0xe1, (byte) 0xce, (byte) 0x69, (byte) 0x63, (byte) 0xb8,
		(byte) 0xd8, (byte) 0xec, (byte) 0xa8, (byte) 0xeb, (byte) 0xd7, (byte) 0x41, (byte) 0xef,
		(byte) 0xb9, (byte) 0xd6, (byte) 0xc4, (byte) 0xea, (byte) 0xd6, (byte) 0xf3, (byte) 0x85,
		(byte) 0x40, (byte) 0x70, (byte) 0x5b, (byte) 0x2b, (byte) 0x20, (byte) 0xd7, (byte) 0xc5,
		(byte) 0xfe, (byte) 0xa6, (byte) 0x1c, (byte) 0x58, (byte) 0x63, (byte) 0x0c, (byte) 0xda,
		(byte) 0xbc, (byte) 0x2d, (byte) 0xc8, (byte) 0x79, (byte) 0x15, (byte) 0x40, (byte) 0xc2,
		(byte) 0x8f, (byte) 0xe8, (byte) 0x23, (byte) 0xbf, (byte) 0x22, (byte) 0xec, (byte) 0xab,
		(byte) 0x17, (byte) 0xc5, (byte) 0x02, (byte) 0xcb, (byte) 0x44, (byte) 0x4a, (byte) 0x66,
		(byte) 0x7d, (byte) 0x7e, (byte) 0xf3, (byte) 0xdd, (byte) 0xa0, (byte) 0x8a, (byte) 0x31,
		(byte) 0xbe, (byte) 0xd8, (byte) 0x03, (byte) 0xc1, (byte) 0x6f, (byte) 0x1a, (byte) 0x42,
		(byte) 0x4b, (byte) 0x4a, (byte) 0xab, (byte) 0xc3, (byte) 0xdc, (byte) 0x56, (byte) 0x35,
		(byte) 0x66, (byte) 0x9a, (byte) 0x48, (byte) 0x69, (byte) 0xec, (byte) 0xe5, (byte) 0x76,
		(byte) 0xa1, (byte) 0x20, (byte) 0xd7, (byte) 0x29, (byte) 0x1c, (byte) 0xec, (byte) 0xe5,
		(byte) 0x49, (byte) 0xd9, (byte) 0xe2, (byte) 0xcb, (byte) 0xac, (byte) 0x45, (byte) 0x63,
		(byte) 0xe0, (byte) 0x3f, (byte) 0xf3, (byte) 0x39, (byte) 0x95, (byte) 0x2c, (byte) 0x22,
		(byte) 0x7b, (byte) 0xda, (byte) 0xd8, (byte) 0xc7, (byte) 0x03, (byte) 0x40, (byte) 0xd3,
		(byte) 0xdf, (byte) 0x47, (byte) 0xa5, (byte) 0xaa, (byte) 0x14, (byte) 0x50, (byte) 0x7b,
		(byte) 0xa1, (byte) 0x02, (byte) 0x03, (byte) 0x01, (byte) 0x00, (byte) 0x01, (byte) 0x02,
		(byte) 0x82, (byte) 0x01, (byte) 0x00, (byte) 0x77, (byte) 0x80, (byte) 0xea, (byte) 0xc1,
		(byte) 0x94, (byte) 0x0f, (byte) 0xc3, (byte) 0x1f, (byte) 0xd6, (byte) 0x2b, (byte) 0x70,
		(byte) 0x75, (byte) 0x2f, (byte) 0xaf, (byte) 0x88, (byte) 0xba, (byte) 0xf7, (byte) 0xdb,
		(byte) 0x92, (byte) 0xa0, (byte) 0x59, (byte) 0x1e, (byte) 0xa7, (byte) 0x1f, (byte) 0x6b,
		(byte) 0x30, (byte) 0x12, (byte) 0xf5, (byte) 0xdb, (byte) 0xf0, (byte) 0x59, (byte) 0xa5,
		(byte) 0x8a, (byte) 0xe5, (byte) 0x30, (byte) 0x4c, (byte) 0x67, (byte) 0x5a, (byte) 0x87,
		(byte) 0xf6, (byte) 0x17, (byte) 0x3d, (byte) 0x7e, (byte) 0xf7, (byte) 0xb3, (byte) 0x31,
		(byte) 0x3a, (byte) 0x91, (byte) 0x11, (byte) 0xad, (byte) 0x71, (byte) 0x5e, (byte) 0x8c,
		(byte) 0x6e, (byte) 0xf7, (byte) 0x86, (byte) 0xb3, (byte) 0x43, (byte) 0xcd, (byte) 0x40,
		(byte) 0x99, (byte) 0x14, (byte) 0x4f, (byte) 0x97, (byte) 0x7c, (byte) 0xf9, (byte) 0xb1,
		(byte) 0xf9, (byte) 0xf2, (byte) 0x1b, (byte) 0xa0, (byte) 0xba, (byte) 0x8f, (byte) 0x57,
		(byte) 0x33, (byte) 0x17, (byte) 0xeb, (byte) 0x32, (byte) 0xf1, (byte) 0x0f, (byte) 0xbc,
		(byte) 0x21, (byte) 0xa8, (byte) 0x04, (byte) 0x6d, (byte) 0x18, (byte) 0xdb, (byte) 0x95,
		(byte) 0x4e, (byte) 0x75, (byte) 0x2d, (byte) 0x57, (byte) 0x22, (byte) 0x0e, (byte) 0x94,
		(byte) 0xc6, (byte) 0x03, (byte) 0xb9, (byte) 0x65, (byte) 0xf6, (byte) 0xd1, (byte) 0x94,
		(byte) 0x3d, (byte) 0xfc, (byte) 0x8a, (byte) 0xb1, (byte) 0xbc, (byte) 0x9d, (byte) 0x8e,
		(byte) 0x23, (byte) 0x6b, (byte) 0x10, (byte) 0x64, (byte) 0xa2, (byte) 0xd7, (byte) 0x2d,
		(byte) 0x6d, (byte) 0x81, (byte) 0x49, (byte) 0xdf, (byte) 0xfd, (byte) 0xfb, (byte) 0x99,
		(byte) 0x24, (byte) 0x78, (byte) 0x64, (byte) 0x98, (byte) 0xff, (byte) 0x1d, (byte) 0xcc,
		(byte) 0xbc, (byte) 0x88, (byte) 0xd0, (byte) 0xc9, (byte) 0x9f, (byte) 0x90, (byte) 0x03,
		(byte) 0xf5, (byte) 0x49, (byte) 0x4e, (byte) 0x18, (byte) 0xb0, (byte) 0xdd, (byte) 0x91,
		(byte) 0x26, (byte) 0x27, (byte) 0x85, (byte) 0xa4, (byte) 0x8e, (byte) 0x6a, (byte) 0xa4,
		(byte) 0x62, (byte) 0xf7, (byte) 0x2b, (byte) 0x86, (byte) 0x67, (byte) 0x12, (byte) 0x28,
		(byte) 0xcf, (byte) 0xa6, (byte) 0x3f, (byte) 0x44, (byte) 0xa0, (byte) 0xe0, (byte) 0x4f,
		(byte) 0xa5, (byte) 0x2e, (byte) 0x67, (byte) 0x1a, (byte) 0xb7, (byte) 0x20, (byte) 0x29,
		(byte) 0xff, (byte) 0x19, (byte) 0x01, (byte) 0x55, (byte) 0xe0, (byte) 0xe9, (byte) 0x09,
		(byte) 0x4d, (byte) 0x58, (byte) 0x57, (byte) 0xf6, (byte) 0xbb, (byte) 0x4e, (byte) 0x7c,
		(byte) 0x2d, (byte) 0xa2, (byte) 0xfc, (byte) 0x6c, (byte) 0xde, (byte) 0x29, (byte) 0xda,
		(byte) 0x74, (byte) 0xc7, (byte) 0x90, (byte) 0xdc, (byte) 0x7a, (byte) 0x1c, (byte) 0x56,
		(byte) 0x41, (byte) 0x95, (byte) 0x3a, (byte) 0x24, (byte) 0x86, (byte) 0xaa, (byte) 0x76,
		(byte) 0x77, (byte) 0xa7, (byte) 0x5b, (byte) 0x23, (byte) 0x48, (byte) 0xcd, (byte) 0xa0,
		(byte) 0x92, (byte) 0x46, (byte) 0x3c, (byte) 0x5e, (byte) 0x3d, (byte) 0xad, (byte) 0xcd,
		(byte) 0x8d, (byte) 0xdf, (byte) 0xe0, (byte) 0x2e, (byte) 0x97, (byte) 0x24, (byte) 0x05,
		(byte) 0xae, (byte) 0x7c, (byte) 0x5b, (byte) 0x18, (byte) 0x2e, (byte) 0x7d, (byte) 0xf4,
		(byte) 0xb3, (byte) 0xde, (byte) 0x2c, (byte) 0x41, (byte) 0xda, (byte) 0xca, (byte) 0xd3,
		(byte) 0x79, (byte) 0x32, (byte) 0x18, (byte) 0xe7, (byte) 0xe1, (byte) 0x95, (byte) 0x25,
		(byte) 0x96, (byte) 0x32, (byte) 0x7f, (byte) 0x4e, (byte) 0x82, (byte) 0xb0, (byte) 0xc1,
		(byte) 0x02, (byte) 0x81, (byte) 0x81, (byte) 0x00, (byte) 0xf3, (byte) 0xaa, (byte) 0x88,
		(byte) 0xd9, (byte) 0x2a, (byte) 0xb1, (byte) 0xc2, (byte) 0x5d, (byte) 0xe4, (byte) 0xa3,
		(byte) 0x2b, (byte) 0x77, (byte) 0xb8, (byte) 0x17, (byte) 0xf5, (byte) 0x67, (byte) 0xce,
		(byte) 0x41, (byte) 0x35, (byte) 0xfa, (byte) 0xde, (byte) 0xd6, (byte) 0x94, (byte) 0xe8,
		(byte) 0x1f, (byte) 0x6b, (byte) 0xad, (byte) 0xad, (byte) 0xf7, (byte) 0x31, (byte) 0xa0,
		(byte) 0xb8, (byte) 0x7a, (byte) 0x17, (byte) 0x7e, (byte) 0xbd, (byte) 0x88, (byte) 0xb3,
		(byte) 0x63, (byte) 0x09, (byte) 0xa0, (byte) 0xd2, (byte) 0x25, (byte) 0xd7, (byte) 0x04,
		(byte) 0x0b, (byte) 0x8d, (byte) 0x62, (byte) 0x42, (byte) 0xbc, (byte) 0xb9, (byte) 0x61,
		(byte) 0x10, (byte) 0x09, (byte) 0x4b, (byte) 0x30, (byte) 0xf7, (byte) 0x54, (byte) 0x46,
		(byte) 0x32, (byte) 0x23, (byte) 0x7f, (byte) 0xb0, (byte) 0x7b, (byte) 0x43, (byte) 0xa9,
		(byte) 0x59, (byte) 0xa8, (byte) 0xf9, (byte) 0xc2, (byte) 0xeb, (byte) 0xb0, (byte) 0x1e,
		(byte) 0xfe, (byte) 0x55, (byte) 0x1e, (byte) 0x99, (byte) 0x07, (byte) 0x7b, (byte) 0xb0,
		(byte) 0x57, (byte) 0x26, (byte) 0x2e, (byte) 0x99, (byte) 0x9b, (byte) 0x64, (byte) 0x46,
		(byte) 0x54, (byte) 0xf4, (byte) 0x6b, (byte) 0xa8, (byte) 0xc9, (byte) 0x5b, (byte) 0x69,
		(byte) 0xd5, (byte) 0x03, (byte) 0x93, (byte) 0xea, (byte) 0xd9, (byte) 0xd8, (byte) 0xce,
		(byte) 0xe6, (byte) 0x60, (byte) 0xa3, (byte) 0x22, (byte) 0x18, (byte) 0xe9, (byte) 0x7e,
		(byte) 0xc3, (byte) 0xf1, (byte) 0x92, (byte) 0xb1, (byte) 0x4c, (byte) 0x7e, (byte) 0x17,
		(byte) 0x2f, (byte) 0x92, (byte) 0x53, (byte) 0x2c, (byte) 0xec, (byte) 0x3f, (byte) 0x4a,
		(byte) 0xdf, (byte) 0xd9, (byte) 0x82, (byte) 0x28, (byte) 0x25, (byte) 0x95, (byte) 0x02,
		(byte) 0x81, (byte) 0x81, (byte) 0x00, (byte) 0xeb, (byte) 0x03, (byte) 0xcd, (byte) 0xde,
		(byte) 0xdb, (byte) 0x45, (byte) 0xc6, (byte) 0xd7, (byte) 0x3b, (byte) 0x6e, (byte) 0x15,
		(byte) 0x0b, (byte) 0x99, (byte) 0xc2, (byte) 0x76, (byte) 0x02, (byte) 0x91, (byte) 0x14,
		(byte) 0x01, (byte) 0xb2, (byte) 0xb5, (byte) 0xa3, (byte) 0xb2, (byte) 0x54, (byte) 0x8b,
		(byte) 0xf2, (byte) 0x1e, (byte) 0xc0, (byte) 0xc4, (byte) 0xd6, (byte) 0xac, (byte) 0x31,
		(byte) 0xe4, (byte) 0xb1, (byte) 0xf4, (byte) 0xd3, (byte) 0x58, (byte) 0x1a, (byte) 0xec,
		(byte) 0x75, (byte) 0x71, (byte) 0xc8, (byte) 0x90, (byte) 0x36, (byte) 0x09, (byte) 0x65,
		(byte) 0xe0, (byte) 0xcc, (byte) 0x55, (byte) 0x46, (byte) 0x5e, (byte) 0xc5, (byte) 0xc5,
		(byte) 0x51, (byte) 0x88, (byte) 0x28, (byte) 0x3a, (byte) 0xb6, (byte) 0xaf, (byte) 0x2a,
		(byte) 0xa9, (byte) 0xb3, (byte) 0x08, (byte) 0xb7, (byte) 0x5d, (byte) 0xc2, (byte) 0x84,
		(byte) 0xb9, (byte) 0xee, (byte) 0x26, (byte) 0x1d, (byte) 0xb9, (byte) 0x1a, (byte) 0x36,
		(byte) 0x8f, (byte) 0x6d, (byte) 0x6c, (byte) 0x9e, (byte) 0x2f, (byte) 0x32, (byte) 0x3a,
		(byte) 0x0a, (byte) 0x05, (byte) 0x19, (byte) 0x29, (byte) 0x7c, (byte) 0x42, (byte) 0x87,
		(byte) 0x48, (byte) 0xaa, (byte) 0x5f, (byte) 0x6c, (byte) 0x0e, (byte) 0x8e, (byte) 0xa3,
		(byte) 0x0c, (byte) 0x99, (byte) 0x3e, (byte) 0xbe, (byte) 0x1b, (byte) 0x2f, (byte) 0x2d,
		(byte) 0xd5, (byte) 0x8c, (byte) 0xbd, (byte) 0x00, (byte) 0x02, (byte) 0x69, (byte) 0x30,
		(byte) 0x37, (byte) 0x5e, (byte) 0x2d, (byte) 0x2e, (byte) 0x09, (byte) 0xaa, (byte) 0xef,
		(byte) 0x87, (byte) 0x9e, (byte) 0x3f, (byte) 0x81, (byte) 0x35, (byte) 0x27, (byte) 0x08,
		(byte) 0xc0, (byte) 0x18, (byte) 0xf1, (byte) 0x62, (byte) 0xdd, (byte) 0x02, (byte) 0x81,
		(byte) 0x81, (byte) 0x00, (byte) 0xbd, (byte) 0xe6, (byte) 0x76, (byte) 0x68, (byte) 0xe9,
		(byte) 0xc1, (byte) 0x47, (byte) 0xfd, (byte) 0xed, (byte) 0x26, (byte) 0xcd, (byte) 0xc5,
		(byte) 0xac, (byte) 0x0f, (byte) 0xe0, (byte) 0x0e, (byte) 0x5a, (byte) 0xcc, (byte) 0xaf,
		(byte) 0xc9, (byte) 0x28, (byte) 0xca, (byte) 0x8b, (byte) 0x9a, (byte) 0xac, (byte) 0x82,
		(byte) 0x3b, (byte) 0x05, (byte) 0x8d, (byte) 0xd5, (byte) 0x7b, (byte) 0xb0, (byte) 0xca,
		(byte) 0x56, (byte) 0x6d, (byte) 0x4c, (byte) 0x41, (byte) 0xb1, (byte) 0xac, (byte) 0xc9,
		(byte) 0xe0, (byte) 0x30, (byte) 0x67, (byte) 0x95, (byte) 0x3f, (byte) 0x6d, (byte) 0xd1,
		(byte) 0x6e, (byte) 0x77, (byte) 0x1c, (byte) 0xa6, (byte) 0x4d, (byte) 0x63, (byte) 0x36,
		(byte) 0x1b, (byte) 0x07, (byte) 0xba, (byte) 0x7a, (byte) 0x4f, (byte) 0x8a, (byte) 0xdb,
		(byte) 0xe7, (byte) 0xb4, (byte) 0x1f, (byte) 0x1d, (byte) 0x08, (byte) 0x6a, (byte) 0xfc,
		(byte) 0x2a, (byte) 0x4b, (byte) 0x23, (byte) 0x6c, (byte) 0x4b, (byte) 0x7b, (byte) 0x63,
		(byte) 0xd3, (byte) 0x48, (byte) 0xe8, (byte) 0x70, (byte) 0x19, (byte) 0x6a, (byte) 0x92,
		(byte) 0x33, (byte) 0x57, (byte) 0x3b, (byte) 0xa7, (byte) 0xd6, (byte) 0xb8, (byte) 0x77,
		(byte) 0x15, (byte) 0x40, (byte) 0xa2, (byte) 0x4d, (byte) 0x40, (byte) 0x19, (byte) 0xe7,
		(byte) 0x83, (byte) 0xec, (byte) 0x50, (byte) 0x83, (byte) 0x8c, (byte) 0x1c, (byte) 0x37,
		(byte) 0xcc, (byte) 0x6b, (byte) 0xd2, (byte) 0x86, (byte) 0x87, (byte) 0x69, (byte) 0x26,
		(byte) 0x68, (byte) 0x71, (byte) 0x0d, (byte) 0x70, (byte) 0x67, (byte) 0x99, (byte) 0x87,
		(byte) 0xac, (byte) 0x93, (byte) 0x22, (byte) 0x3b, (byte) 0xe1, (byte) 0x9a, (byte) 0xbb,
		(byte) 0xe5, (byte) 0x98, (byte) 0x6c, (byte) 0x51, (byte) 0x02, (byte) 0x81, (byte) 0x80,
		(byte) 0x01, (byte) 0x10, (byte) 0xa6, (byte) 0x59, (byte) 0x31, (byte) 0x33, (byte) 0x32,
		(byte) 0xc0, (byte) 0x7c, (byte) 0xf3, (byte) 0x75, (byte) 0xc2, (byte) 0xf4, (byte) 0xb2,
		(byte) 0x6d, (byte) 0xe8, (byte) 0x7b, (byte) 0x11, (byte) 0xd5, (byte) 0x24, (byte) 0x23,
		(byte) 0x30, (byte) 0x97, (byte) 0xb9, (byte) 0x4c, (byte) 0x5d, (byte) 0x0f, (byte) 0x88,
		(byte) 0x9e, (byte) 0x1b, (byte) 0xbe, (byte) 0xf2, (byte) 0x06, (byte) 0xf0, (byte) 0x4b,
		(byte) 0x84, (byte) 0xbd, (byte) 0xac, (byte) 0x79, (byte) 0x8f, (byte) 0xda, (byte) 0xb1,
		(byte) 0x26, (byte) 0xfe, (byte) 0x27, (byte) 0xb2, (byte) 0xbf, (byte) 0x7f, (byte) 0x0d,
		(byte) 0x8f, (byte) 0xe1, (byte) 0x14, (byte) 0x12, (byte) 0x5d, (byte) 0xd9, (byte) 0x39,
		(byte) 0x1d, (byte) 0x73, (byte) 0x00, (byte) 0x7e, (byte) 0x38, (byte) 0x00, (byte) 0xa8,
		(byte) 0xb4, (byte) 0x74, (byte) 0x07, (byte) 0x52, (byte) 0xa4, (byte) 0xa9, (byte) 0x10,
		(byte) 0xa1, (byte) 0x27, (byte) 0xda, (byte) 0x97, (byte) 0x8e, (byte) 0xb4, (byte) 0xd7,
		(byte) 0x3e, (byte) 0x2c, (byte) 0x46, (byte) 0x94, (byte) 0xfe, (byte) 0xc0, (byte) 0xa1,
		(byte) 0x29, (byte) 0x8f, (byte) 0xf7, (byte) 0x99, (byte) 0x37, (byte) 0x5a, (byte) 0x16,
		(byte) 0x4e, (byte) 0x9e, (byte) 0x0e, (byte) 0x45, (byte) 0x6c, (byte) 0xe4, (byte) 0x30,
		(byte) 0xe5, (byte) 0x99, (byte) 0xa7, (byte) 0xf0, (byte) 0x14, (byte) 0x3c, (byte) 0xac,
		(byte) 0x0a, (byte) 0x98, (byte) 0xf8, (byte) 0x33, (byte) 0x10, (byte) 0xbd, (byte) 0x2b,
		(byte) 0x85, (byte) 0x3e, (byte) 0xe3, (byte) 0xf8, (byte) 0x6b, (byte) 0xeb, (byte) 0xea,
		(byte) 0xab, (byte) 0xc2, (byte) 0x3a, (byte) 0xe8, (byte) 0x0e, (byte) 0x3e, (byte) 0xce,
		(byte) 0xb1, (byte) 0x3d, (byte) 0x02, (byte) 0x81, (byte) 0x80, (byte) 0x4c, (byte) 0x31,
		(byte) 0x68, (byte) 0x98, (byte) 0x9e, (byte) 0xea, (byte) 0x63, (byte) 0x4a, (byte) 0x20,
		(byte) 0xb5, (byte) 0xa3, (byte) 0xbc, (byte) 0xc8, (byte) 0xed, (byte) 0xe1, (byte) 0x38,
		(byte) 0x6f, (byte) 0xe1, (byte) 0xea, (byte) 0x4b, (byte) 0x34, (byte) 0x53, (byte) 0x7e,
		(byte) 0x07, (byte) 0x48, (byte) 0x43, (byte) 0x67, (byte) 0x11, (byte) 0xba, (byte) 0x24,
		(byte) 0xf9, (byte) 0x3c, (byte) 0x09, (byte) 0x01, (byte) 0xd7, (byte) 0xb1, (byte) 0x16,
		(byte) 0x1b, (byte) 0x00, (byte) 0xd8, (byte) 0x7d, (byte) 0xc9, (byte) 0x86, (byte) 0x6f,
		(byte) 0x1a, (byte) 0x4e, (byte) 0x97, (byte) 0xa4, (byte) 0x0a, (byte) 0xf1, (byte) 0x38,
		(byte) 0x87, (byte) 0x5c, (byte) 0x64, (byte) 0x4e, (byte) 0x8a, (byte) 0x91, (byte) 0xd8,
		(byte) 0xe6, (byte) 0xa4, (byte) 0xdc, (byte) 0xc2, (byte) 0x51, (byte) 0x92, (byte) 0x75,
		(byte) 0xc8, (byte) 0xe3, (byte) 0x97, (byte) 0xd0, (byte) 0x1c, (byte) 0xbb, (byte) 0xd0,
		(byte) 0x33, (byte) 0xf4, (byte) 0xe2, (byte) 0x62, (byte) 0x32, (byte) 0x17, (byte) 0x2a,
		(byte) 0x3b, (byte) 0x0c, (byte) 0xd3, (byte) 0xa4, (byte) 0xab, (byte) 0xef, (byte) 0xd3,
		(byte) 0x12, (byte) 0x83, (byte) 0x96, (byte) 0xc7, (byte) 0xe6, (byte) 0x22, (byte) 0xec,
		(byte) 0x2b, (byte) 0x35, (byte) 0x1a, (byte) 0xae, (byte) 0x45, (byte) 0x7e, (byte) 0xd7,
		(byte) 0x26, (byte) 0x1c, (byte) 0xbd, (byte) 0x0f, (byte) 0xe0, (byte) 0xde, (byte) 0xdf,
		(byte) 0x92, (byte) 0x75, (byte) 0x8e, (byte) 0x9b, (byte) 0x49, (byte) 0x00, (byte) 0x7b,
		(byte) 0x99, (byte) 0x2f, (byte) 0xa6, (byte) 0x52, (byte) 0x7f, (byte) 0x0c, (byte) 0x5d,
		(byte) 0xb6, (byte) 0x2c, (byte) 0xab, (byte) 0xd0, (byte) 0x8b, (byte) 0x1d, (byte) 0xd6
	};
	private static final String[] CDP = { "http://nharu.crypthing.org/repo" };
	private static final String MS_UPN = "imyself@microsofot.com";
	private static final String SUBJECT_ID = "000000000000000000000000000000000000000000000DETRANRJ";
	private static final String SUBJECT_TE = "0000000000000000000Rio de Janeiro      RJ";
	private static final String SUBJECT_CEI = "000000000000";
	private static class CADemo implements SignerInterface
	{
		final private NharuX509Certificate caCert;
		final private NharuRSAPrivateKey caKey;
		final CertificateParams params;
		final CertificateProfile profile;
		private BigInteger serial;
		CADemo() throws CertificateException, InvalidKeyException
		{
			caCert = new NharuX509Certificate(CA_CERT.getBytes());
			caKey = new NharuRSAPrivateKey(CA_KEY);
			params = new CertificateParams(caCert, CDP);
			profile = new UserProfile();
			serial = BigInteger.ZERO;
		}
		CertificateParams getParams() { return (CertificateParams) params.clone(); }
		BigInteger getSerial() { return (serial = serial.add(BigInteger.ONE)); }
		void release()
		{
			caCert.closeHandle();
			caKey.releaseObject();;
		}
		byte[] issue(final String json) throws GeneralSecurityException
		{
			final NharuCertificateEncoder cert = new NharuCertificateEncoder(json, profile);
			try
			{
				cert.sign("SHA256withRSA", this);
				return cert.encode();
			}
			finally { cert.releaseObject(); }
		}
		@Override public int signatureLength(final String algorithm) { return caKey.signatureLength(algorithm); }
		@Override public byte[] sign(final byte[] data, final String algorithm) throws GeneralSecurityException { return caKey.sign(data, algorithm); }
	}
	private static class ARDemo
	{
		final private CADemo ca;
		ARDemo(final CADemo ca) { this.ca = ca; }
		byte[] issue(final byte[] pkcs10) throws GeneralSecurityException
		{
			final NharuCertificateRequest request = NharuCertificateRequest.parse(pkcs10);
			try
			{
				request.verify();
				final CertificateParams params = ca.getParams();
				params.setSerial(ca.getSerial());
				params.setSubject(request.getSubject().getName());
				params.setPublicKey(request.getPublicKey());
				final NharuOtherName[] subjectAltName = new NharuOtherName[4];
				subjectAltName[0] = new MicrosoftUPN(MS_UPN);
				subjectAltName[1] = new SubjectID(SUBJECT_ID);
				subjectAltName[2] = new SubjectTE(SUBJECT_TE);
				subjectAltName[3] = new SubjectCEI(SUBJECT_CEI);
				params.setSubjectAltName(subjectAltName);
				return ca.issue(params.toString());
			}
			finally { request.releaseObject(); }
		}
	}
	public static void throughputTest()
	{
		try
		{
			final CADemo ca = new CADemo();
			final ARDemo ar = new ARDemo(ca);
			final byte[] pkcs10 = NharuCertificateRequest.CERTIFICATE_REQUEST.getBytes();
			try
			{
				for (int i = 0; i < 100; i++)  ar.issue(pkcs10);
				final long t0 = System.nanoTime();
				for (int i = 0; i < 1000; i++)  ar.issue(pkcs10);
				final long t1 = System.nanoTime();
				long timed = (t1 - t0);
				double sec = timed / 1e9d;
				System.out.println("Issue throughput: " + 1000/sec);
			}
			finally { ca.release(); }
		}
		catch (Exception e) { e.printStackTrace(); }
	}
	public static void main(String[] args)
	{
		if (args.length == 0) regressionTest();
		else throughputTest();
	}
	private static void regressionTest()
	{
		boolean result = false;
		System.out.print("Validating certificate issuing... ");
		final byte[] encoding = sign();
		if (encoding != null) result = validate(encoding);
		if (result) System.out.println("Done!");
		else System.err.println("Validation failed");
	}
	private static byte[] sign()
	{
		byte[] ret = null;
		try
		{
			final NharuX509Certificate caCert = new NharuX509Certificate(CA_CERT.getBytes());
			try
			{
				final NharuRSAPrivateKey caKey = new NharuRSAPrivateKey(CA_KEY);
				try
				{
					final CertificateParams params = new CertificateParams(caCert, CDP);
					final CertificateProfile profile = new UserProfile();
					BigInteger serial = BigInteger.ZERO;

					final NharuCertificateRequest request = NharuCertificateRequest.parse(NharuCertificateRequest.CERTIFICATE_REQUEST.getBytes());
					request.verify();
					final CertificateParams current = (CertificateParams) params.clone();
					serial = serial.add(BigInteger.ONE);
					current.setSerial(serial);
					current.setSubject(request.getSubject().getName());
					current.setPublicKey(request.getPublicKey());
					final NharuOtherName[] subjectAltName = new NharuOtherName[4];
					subjectAltName[0] = new MicrosoftUPN(MS_UPN);
					subjectAltName[1] = new SubjectID(SUBJECT_ID);
					subjectAltName[2] = new SubjectTE(SUBJECT_TE);
					subjectAltName[3] = new SubjectCEI(SUBJECT_CEI);
					current.setSubjectAltName(subjectAltName);
					final String json = current.toString();

					final NharuCertificateEncoder cert = new NharuCertificateEncoder(json, profile);
					try
					{
						cert.sign("SHA256withRSA", new SignerInterface()
						{
							@Override public int signatureLength(String algorithm)
							{
								return caKey.signatureLength(algorithm);
							}
							@Override public byte[] sign(byte[] data, String algorithm) throws GeneralSecurityException
							{
								return caKey.sign(data, algorithm);
							}
						});
						ret = cert.encode();
					}
					finally { cert.releaseObject(); }
				}
				finally { caKey.releaseObject(); }
			}
			finally { caCert.closeHandle(); }
		}
		catch (Exception e) { e.printStackTrace(); }
		return ret;
	}
	private static boolean validate(final byte[] encoding)
	{
		boolean ret = true;
		try
		{
			final NharuX509Certificate caCert = new NharuX509Certificate(CA_CERT.getBytes());
			try
			{
				final NharuX509Certificate cert = new NharuX509Certificate(encoding);
				try
				{
					cert.verify(caCert.getPublicKey());
					final NharuCertificateRequest request = NharuCertificateRequest.parse(NharuCertificateRequest.CERTIFICATE_REQUEST.getBytes());
					try
					{
						if (!cert.getSubjectX500Principal().getName().equals(request.getSubject().getName())) throw new RuntimeException("Certificagte subject does not match");
						final NharuPKIBRParser pkiBR = NharuPKIBRParser.parse(cert);
						try
						{
							if
							(
								!Arrays.equals(pkiBR.getSubjectId(), SUBJECT_ID.toCharArray()) ||
								!Arrays.equals(pkiBR.getSubjectTE(), SUBJECT_TE.toCharArray()) ||
								!Arrays.equals(pkiBR.getSubjectCEI(), SUBJECT_CEI.toCharArray())
							)	throw new RuntimeException("Certificate Subject Alternative Name extensions does not match");
						}
						finally { pkiBR.releaseParser(); }
					}
					finally { request.releaseObject(); }
				}
				finally { cert.closeHandle(); }
			}
			finally { caCert.closeHandle(); }
		}
		catch (Exception e) { e.printStackTrace(); ret = false; }
		return ret;
	}
}