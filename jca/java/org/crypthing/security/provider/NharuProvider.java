package org.crypthing.security.provider;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Provider;
import java.util.Enumeration;

import org.crypthing.security.LogDevice;
import org.crypthing.security.cert.NharuCertStore;
import org.crypthing.security.cms.CMSDocument;
import org.crypthing.security.x509.NharuPKIBRParser;
import org.crypthing.security.x509.NharuX509CRL;
import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.util.NharuArrays;

import static org.crypthing.security.LogDevice.LOG_LEVEL;
import static org.crypthing.security.LogDevice.LOG_LEVEL_DEBUG;
import static org.crypthing.security.LogDevice.LOG_LEVEL_INFO;
import static org.crypthing.security.LogDevice.LOG_LEVEL_NONE;


public final class NharuProvider extends Provider
{
	private static final String ERROR_SO_NOT_FOUND = "Could not find native library in JAR file";
	private static final String ERROR_LOAD_SO = "Could not load native library due to following error: ";
	private static final LogDevice LOG = new LogDevice(NharuProvider.class.getName());

	private static final long serialVersionUID = 8247503976486321933L;
	public static final String NHARU_PROVIDER_NAME = "Nharu";
	public static final double NHARU_VERSION = 2.0;

	static
	{
		try { System.loadLibrary("nharujca"); }
		catch (final UnsatisfiedLinkError e)
		{
			try
			{
				String lib = "libnharujca.so";
				if (System.getProperty("os.name", "").toLowerCase().indexOf("win") >= 0) lib = "nharujca.dll";
				final File workaround = new File(lib);
				if (workaround.exists()) workaround.delete();
				final File libFile = new File(lib);
				libFile.deleteOnExit();
				final OutputStream out = new FileOutputStream(libFile);
				try
				{
					final InputStream in = NharuProvider.class.getResourceAsStream("/" + lib);
					if (in == null)
					{
						if (LOG_LEVEL < LOG_LEVEL_NONE) LOG.fatal(ERROR_SO_NOT_FOUND);
						throw new UnsatisfiedLinkError(ERROR_SO_NOT_FOUND);
					}
					try
					{
						final byte[] buffer = new byte[4096];
						int i;
						while ((i = in.read(buffer)) != -1) out.write(buffer, 0, i);
					}
					finally { in.close(); }
				}
				finally { out.close(); }
				System.load(libFile.getAbsolutePath());
			}
			catch (final Exception f)
			{
				if (LOG_LEVEL < LOG_LEVEL_NONE) LOG.fatal(ERROR_LOAD_SO, f);
				UnsatisfiedLinkError g = new UnsatisfiedLinkError(ERROR_LOAD_SO + f.getMessage());
				g.initCause(f);
				throw g;
			}
			catch(final UnsatisfiedLinkError f)
			{
				if (LOG_LEVEL < LOG_LEVEL_NONE) LOG.fatal(ERROR_LOAD_SO, f);
				throw f;
			}
		}
	}
	public static boolean isLoaded() { return true; }

	public NharuProvider()
	{
		super(NHARU_PROVIDER_NAME, NHARU_VERSION, "X.509 certificates Provider");
		if (LOG_LEVEL < LOG_LEVEL_DEBUG)
		{
			final StringBuilder builder = new StringBuilder();
			final Enumeration<?> en = propertyNames();
			builder.append("Provider values:\n");
			while (en.hasMoreElements())
			{
				final String name = (String) en.nextElement();
				builder.append(name);
				builder.append(" = ");
				builder.append(getProperty(name, "none"));
				builder.append("\n");
			}
			LOG.trace(builder.toString());
		}
		put("CertificateFactory.X.509", "org.crypthing.security.x509.NharuX509Factory");
		put("Alg.Alias.CertificateFactory.X509", "X.509");
		put("CertificateFactory.X.509 ImplementedIn", "Software");

		put("CertStore.Collection", "org.crypthing.cert.NharuCertStore");
		put("CertStore.Collection ImplementedIn", "Software");

		put("TrustManagerFactory.PKIX", "org.crypthing.security.x509.NharuTrustManagerFactory");
		put("Alg.Alias.TrustManagerFactory.SunPKIX", "PKIX");
		put("Alg.Alias.TrustManagerFactory.X509", "PKIX");
		put("Alg.Alias.TrustManagerFactory.X.509", "PKIX");	

//		paramMap.put("CertPathBuilder.PKIX", "sun.security.provider.certpath.SunCertPathBuilder");
//		paramMap.put("CertPathBuilder.PKIX ValidationAlgorithm", "RFC3280");
//		paramMap.put("CertPathValidator.PKIX", "sun.security.provider.certpath.PKIXCertPathValidator");
//		paramMap.put("CertPathValidator.PKIX ValidationAlgorithm", "RFC3280");
//		paramMap.put("CertPathValidator.PKIX ImplementedIn", "Software");
//		paramMap.put("CertPathBuilder.PKIX ImplementedIn", "Software");


	}


/*
    String str = "java.security.interfaces.DSAPublicKey|java.security.interfaces.DSAPrivateKey";

    paramMap.put("SecureRandom.NativePRNG", "sun.security.provider.NativePRNG");
    paramMap.put("SecureRandom.SHA1PRNG", "sun.security.provider.SecureRandom");
    paramMap.put("Signature.SHA1withDSA", "sun.security.provider.DSA$SHA1withDSA");
    paramMap.put("Signature.NONEwithDSA", "sun.security.provider.DSA$RawDSA");
    paramMap.put("Alg.Alias.Signature.RawDSA", "NONEwithDSA");
    paramMap.put("Signature.SHA1withDSA SupportedKeyClasses", str);
    paramMap.put("Signature.NONEwithDSA SupportedKeyClasses", str);
    paramMap.put("Alg.Alias.Signature.DSA", "SHA1withDSA");
    paramMap.put("Alg.Alias.Signature.DSS", "SHA1withDSA");
    paramMap.put("Alg.Alias.Signature.SHA/DSA", "SHA1withDSA");
    paramMap.put("Alg.Alias.Signature.SHA-1/DSA", "SHA1withDSA");
    paramMap.put("Alg.Alias.Signature.SHA1/DSA", "SHA1withDSA");
    paramMap.put("Alg.Alias.Signature.SHAwithDSA", "SHA1withDSA");
    paramMap.put("Alg.Alias.Signature.DSAWithSHA1", "SHA1withDSA");
    paramMap.put("Alg.Alias.Signature.OID.1.2.840.10040.4.3", "SHA1withDSA");
    paramMap.put("Alg.Alias.Signature.1.2.840.10040.4.3", "SHA1withDSA");
    paramMap.put("Alg.Alias.Signature.1.3.14.3.2.13", "SHA1withDSA");
    paramMap.put("Alg.Alias.Signature.1.3.14.3.2.27", "SHA1withDSA");

    paramMap.put("KeyPairGenerator.DSA", "sun.security.provider.DSAKeyPairGenerator");
    paramMap.put("Alg.Alias.KeyPairGenerator.OID.1.2.840.10040.4.1", "DSA");
    paramMap.put("Alg.Alias.KeyPairGenerator.1.2.840.10040.4.1", "DSA");
    paramMap.put("Alg.Alias.KeyPairGenerator.1.3.14.3.2.12", "DSA");

    paramMap.put("MessageDigest.MD2", "sun.security.provider.MD2");
    paramMap.put("MessageDigest.MD5", "sun.security.provider.MD5");
    paramMap.put("MessageDigest.SHA", "sun.security.provider.SHA");
    paramMap.put("Alg.Alias.MessageDigest.SHA-1", "SHA");
    paramMap.put("Alg.Alias.MessageDigest.SHA1", "SHA");
    paramMap.put("MessageDigest.SHA-256", "sun.security.provider.SHA2");
    paramMap.put("MessageDigest.SHA-384", "sun.security.provider.SHA5$SHA384");
    paramMap.put("MessageDigest.SHA-512", "sun.security.provider.SHA5$SHA512");

    paramMap.put("AlgorithmParameterGenerator.DSA", "sun.security.provider.DSAParameterGenerator");
    paramMap.put("AlgorithmParameters.DSA", "sun.security.provider.DSAParameters");
    paramMap.put("Alg.Alias.AlgorithmParameters.1.3.14.3.2.12", "DSA");
    paramMap.put("Alg.Alias.AlgorithmParameters.1.2.840.10040.4.1", "DSA");

    paramMap.put("KeyFactory.DSA", "sun.security.provider.DSAKeyFactory");
    paramMap.put("Alg.Alias.KeyFactory.1.3.14.3.2.12", "DSA");
    paramMap.put("Alg.Alias.KeyFactory.1.2.840.10040.4.1", "DSA");

    paramMap.put("KeyStore.JKS", "sun.security.provider.JavaKeyStore$JKS");
    paramMap.put("KeyStore.CaseExactJKS", "sun.security.provider.JavaKeyStore$CaseExactJKS");

    paramMap.put("Policy.JavaPolicy", "sun.security.provider.PolicySpiFile");

    paramMap.put("Configuration.JavaLoginConfig", "sun.security.provider.ConfigSpiFile");

    paramMap.put("CertStore.LDAP", "sun.security.provider.certpath.ldap.LDAPCertStore");
    paramMap.put("CertStore.LDAP LDAPSchema", "RFC2587");
    paramMap.put("CertStore.com.sun.security.IndexedCollection", "sun.security.provider.certpath.IndexedCollectionCertStore");

    paramMap.put("Signature.SHA1withDSA KeySize", "1024");
    paramMap.put("KeyPairGenerator.DSA KeySize", "1024");
    paramMap.put("AlgorithmParameterGenerator.DSA KeySize", "1024");

    paramMap.put("Signature.SHA1withDSA ImplementedIn", "Software");
    paramMap.put("KeyPairGenerator.DSA ImplementedIn", "Software");
    paramMap.put("MessageDigest.MD5 ImplementedIn", "Software");
    paramMap.put("MessageDigest.SHA ImplementedIn", "Software");
    paramMap.put("AlgorithmParameterGenerator.DSA ImplementedIn", "Software");

    paramMap.put("AlgorithmParameters.DSA ImplementedIn", "Software");
    paramMap.put("KeyFactory.DSA ImplementedIn", "Software");
    paramMap.put("SecureRandom.SHA1PRNG ImplementedIn", "Software");
    paramMap.put("KeyStore.JKS ImplementedIn", "Software");
    paramMap.put("CertStore.LDAP ImplementedIn", "Software");
    paramMap.put("CertStore.com.sun.security.IndexedCollection ImplementedIn", "Software");

    put("TrustManagerFactory.SunX509", "sun.security.ssl.TrustManagerFactoryImpl$SimpleFactory");

  As seen in sun.security.ssl.SunJSSE  

      put("KeyFactory.RSA", "sun.security.rsa.RSAKeyFactory");
      put("Alg.Alias.KeyFactory.1.2.840.113549.1.1", "RSA");
      put("Alg.Alias.KeyFactory.OID.1.2.840.113549.1.1", "RSA");
      put("KeyPairGenerator.RSA", "sun.security.rsa.RSAKeyPairGenerator");
      put("Alg.Alias.KeyPairGenerator.1.2.840.113549.1.1", "RSA");
      put("Alg.Alias.KeyPairGenerator.OID.1.2.840.113549.1.1", "RSA");

      put("Signature.MD2withRSA", "sun.security.rsa.RSASignature$MD2withRSA");
      put("Alg.Alias.Signature.1.2.840.113549.1.1.2", "MD2withRSA");
      put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.2", "MD2withRSA");

      put("Signature.MD5withRSA", "sun.security.rsa.RSASignature$MD5withRSA");
      put("Alg.Alias.Signature.1.2.840.113549.1.1.4", "MD5withRSA");
      put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.4", "MD5withRSA");

      put("Signature.SHA1withRSA", "sun.security.rsa.RSASignature$SHA1withRSA");
      put("Alg.Alias.Signature.1.2.840.113549.1.1.5", "SHA1withRSA");
      put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.5", "SHA1withRSA");

      put("Alg.Alias.Signature.1.3.14.3.2.29", "SHA1withRSA");
      put("Alg.Alias.Signature.OID.1.3.14.3.2.29", "SHA1withRSA");

    put("Signature.MD5andSHA1withRSA", "sun.security.ssl.RSASignature");

    put("KeyManagerFactory.SunX509", "sun.security.ssl.KeyManagerFactoryImpl$SunX509");
    put("KeyManagerFactory.NewSunX509", "sun.security.ssl.KeyManagerFactoryImpl$X509");
    put("Alg.Alias.KeyManagerFactory.PKIX", "NewSunX509");

    put("SSLContext.TLSv1", "sun.security.ssl.SSLContextImpl$TLS10Context");
    put("Alg.Alias.SSLContext.TLS", "TLSv1");
    if (!paramBoolean) {
      put("Alg.Alias.SSLContext.SSL", "TLSv1");
      put("Alg.Alias.SSLContext.SSLv3", "TLSv1");
    }

    put("SSLContext.TLSv1.1", "sun.security.ssl.SSLContextImpl$TLS11Context");
    put("SSLContext.TLSv1.2", "sun.security.ssl.SSLContextImpl$TLS12Context");
    put("SSLContext.Default", "sun.security.ssl.SSLContextImpl$DefaultSSLContext");

    put("KeyStore.PKCS12", "sun.security.pkcs12.PKCS12KeyStore");
*/




	/*
	 * Basic tests
	 * ==================================
	 */
	public static void main(final String[] args)
	{
		if (LOG_LEVEL < LOG_LEVEL_INFO)
		{
			System.out.println("====================================================================");
			NharuArrays.main(new String[0]);
			System.out.println("====================================================================");
			NharuX509Certificate.main(new String[0]);
			System.out.println("====================================================================");
			NharuPKIBRParser.main(new String[0]);
			System.out.println("====================================================================");
			NharuX509CRL.main(new String[0]);
			System.out.println("====================================================================");
			NharuCertStore.main(new String[0]);
			System.out.println("====================================================================");
			final String p12 = args.length == 1 ? args[0] : "signer.p12";
			System.setProperty("javax.net.ssl.keyStore", p12);
			System.setProperty("javax.net.ssl.keyStorePassword", "secret");
			System.setProperty("javax.net.ssl.keyStoreType", "pkcs12");
			CMSDocument.main(new String[0]);
			System.out.println("====================================================================");
		}
	}
}


