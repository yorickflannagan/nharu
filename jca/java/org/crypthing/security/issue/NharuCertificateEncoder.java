package org.crypthing.security.issue;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;

import org.crypthing.security.EncodingException;
import org.crypthing.security.NharuX500Name;
import org.crypthing.security.SignerInterface;
import org.crypthing.security.provider.NharuProvider;
import org.crypthing.util.NharuCommon;

public class NharuCertificateEncoder
{

	static { NharuProvider.isLoaded(); }
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws NotSerializableException { throw new NotSerializableException(); }

	private long hHandle = 0;
	private boolean signed = false;
	private byte[] encoding = null;
	/**
	 * Creates a new instance of certificate encoder
	 * @param json: CertificateParams JSON message
	 * @param profile: profile to check
	 * @throws ParameterException on invalid parameter
	 * @throws CertificateProfileException on profile error
	 */
	public NharuCertificateEncoder(final String json, final CertificateProfile profile) throws ParameterException, CertificateProfileException { this(new CertificateParams(json), profile); }
	/**
	 * Creates a new instance of certificate encoder
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
	 * @param algorithm: signature algorithm. Only SHA1withRSA, SHA256withRSA,
	 *                   SHA384withRSA, SHA512withRSA and MD5withRSA are supported.
	 *                   Must conform signature field of certificate profile.
	 * @param signer:    signing callback. Must also implements
	 *                   java.security.interfaces.RSAPrivateKey.
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
		if (hHandle != 0) nhceReleaseCertificageEncoder(hHandle);
		hHandle = 0;
	}
	private static native long nhceNewCertificateEncoder();
	private static native void nhceReleaseCertificageEncoder(long handle);
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
	private static native byte[] nhceEncode(long handle) throws  EncodingException;


	static final String CA_CERT =
		"-----BEGIN CERTIFICATE-----\n" + 
		"MIIEbjCCA1agAwIBAgIBADANBgkqhkiG9w0BAQsFADB2MQswCQYDVQQGEwJCUjET\n" + 
		"MBEGA1UEChMKUEtJIEJyYXppbDEfMB0GA1UECxMWUEtJIFJ1bGVyIGZvciBBbGwg\n" + 
		"Q2F0czExMC8GA1UEAxMoQ29tbW9uIE5hbWUgZm9yIEFsbCBDYXRzIEludGVybWVk\n" + 
		"aWF0ZSBDQTAgFw0xOTA0MTYyMDIyMDlaGA8yMTE5MDQxNDIwMjIwOVowcjELMAkG\n" + 
		"A1UEBhMCQlIxEzARBgNVBAoTClBLSSBCcmF6aWwxHzAdBgNVBAsTFlBLSSBSdWxl\n" + 
		"ciBmb3IgQWxsIENhdHMxLTArBgNVBAMTJENvbW1vbiBOYW1lIGZvciBBbGwgQ2F0\n" + 
		"cyBFbmQgVXNlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN+x\n" + 
		"KpKi6o5QQ3fBxEdHzgF3drtxtf9bu+365cAOyTPW+GLv5X/jzP9hRdu2jAq/HhFc\n" + 
		"pdw+dCPXBBVppLyfDPv30cgqJU00MV6glZ8t99eKo9o+OU2hmGSu+XJ5uNqzjWnX\n" + 
		"TORqqEjjuRen5wsIhQszD1L53PPboD5wiVhO6qFrh+dbwrzHfErSt+HOaWO42Oyo\n" + 
		"69dB77nWxOrW84VAcFsrINfF/qYcWGMM2rwtyHkVQMKP6CO/IuyrF8UCy0RKZn1+\n" + 
		"892gijG+2APBbxpCS0qrw9xWNWaaSGns5XahINcpHOzlSdniy6xFY+A/8zmVLCJ7\n" + 
		"2tjHA0DT30elqhRQe6ECAwEAAaOCAQcwggEDMB0GA1UdDgQWBBR2JuZeNIoZo0sT\n" + 
		"bqUAG7vtS7Q9VTCBmAYDVR0jBIGQMIGNgBQGBpoixKfA+FX+BeqGNwqNLcAX06Fy\n" + 
		"pHAwbjELMAkGA1UEBhMCQlIxEzARBgNVBAoTClBLSSBCcmF6aWwxHzAdBgNVBAsT\n" + 
		"FlBLSSBSdWxlciBmb3IgQWxsIENhdHMxKTAnBgNVBAMTIENvbW1vbiBOYW1lIGZv\n" + 
		"ciBBbGwgQ2F0cyBSb290IENBggEAMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEG\n" + 
		"MCwGA1UdHwQlMCMwIaAfoB2GG2h0dHA6Ly9sb2NhbGhvc3QvYWMvZW5kLmNybDAN\n" + 
		"BgkqhkiG9w0BAQsFAAOCAQEAkd5aPwlz+Awur21hH6W3Yk/opvQfBy+7ChuDk4n7\n" + 
		"Cl2LyVyHAAuYyOPqCsalG5exQcJMgdGrVmaFSMmzOWIpaS3uffxuvA0wRX0BPIm1\n" + 
		"aC42Wz8pxODn2go2FjsAoEywhQSBmOAL1tCOYLzaTzdY43CAhYxzLlh6Ykl+ug/S\n" + 
		"TshTApAu53e+NnC5d6pmGsEwGbyh+oYVo1zahUS9iwtb0K9nvnk3NZti7HMgxq1r\n" + 
		"HNfej9EFvlm9TfktaaQOnTEhRHPDLmb5FuGFmZkaQWkDrUU/ikT3J+vCmRCV+Fl4\n" + 
		"fASwi3itqEIwQES/JyJTTAiEToGPf7j5bWbrPy1yZNh0iA==\n" + 
		"-----END CERTIFICATE-----";
	public static void main(String[] args)
	{

	}
}