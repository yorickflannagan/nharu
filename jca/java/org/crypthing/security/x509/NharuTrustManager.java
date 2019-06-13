package org.crypthing.security.x509;

import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedTrustManager;

import org.crypthing.security.cert.NharuCertStore;
import org.crypthing.security.cert.X509CertCollectionParams;
import org.crypthing.security.LogDevice;

import sun.security.util.HostnameChecker;
import static org.crypthing.security.LogDevice.LOG_LEVEL;
import static org.crypthing.security.LogDevice.LOG_LEVEL_DEBUG;
import static org.crypthing.security.LogDevice.LOG_LEVEL_INFO;
import static org.crypthing.security.LogDevice.LOG_LEVEL_FATAL;
import static org.crypthing.security.LogDevice.LOG_LEVEL_NONE;

public class NharuTrustManager extends X509ExtendedTrustManager 
{
	private static final String FATAL_ENV = "Invalid environment";
	private static final String FATAL_PARAM = "Invalid TrustManager constructor parameter";
	private static final String ERROR_CHAIN = "Chain argument must not be NULL nor zero-length";
	private static final String ERROR_AUTH_TYPE = "Authentication type must not be NULL nor zero-length";
	private static final String DBG_PEER_CERT = "Must check certificate issued to ";
	private static final LogDevice LOG = new LogDevice(NharuTrustManager.class.getName());

	private static final String CRL_CHECKER_FACTORY_ENTRY = "org.crypthing.security.x509.CRLCheckerFactory";
	private static final String ENDPOINT_VALIDATE_ENTRY = "org.crypthing.security.x509.PeerAddressValidate";
	private static final CRLCheckerFactory CHECKER;
	private static final boolean ENDPOINT_VALIDATE;
	static
	{
		
		final String def = System.getProperty(CRL_CHECKER_FACTORY_ENTRY);
		if (def == null) CHECKER = null;
		else
		{
			try { CHECKER = (CRLCheckerFactory) Class.forName(def).newInstance(); }
			catch (final InstantiationException | IllegalAccessException | ClassNotFoundException e) { throw new RuntimeException(FATAL_ENV, e); }
		}
		ENDPOINT_VALIDATE = Boolean.getBoolean(ENDPOINT_VALIDATE_ENTRY);
	}

	private final NharuCertStore certs;
	private X509Certificate[] issuers = null;

	public NharuTrustManager(final KeyStore ks) throws KeyStoreException
	{
		if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack();
		try { certs = new NharuCertStore(new X509CertCollectionParams(ks)); }
		catch (InvalidAlgorithmParameterException e)
		{
			if (LOG_LEVEL < LOG_LEVEL_NONE) LOG.fatal(FATAL_PARAM, e);
			throw new KeyStoreException(e);
		}
		final Iterator<NharuX509Certificate> it = certs.iterator();
		while (it.hasNext()) NharuX509Factory.cachePromote(it.next());
	}

	private void checkTrusted(final X509Certificate[] chain) throws CertificateException
	{
		if (chain == null || chain.length == 0)
		{
			if (LOG_LEVEL < LOG_LEVEL_FATAL) LOG.error(ERROR_CHAIN);
			throw new IllegalArgumentException(ERROR_CHAIN);
		}
		if (LOG_LEVEL < LOG_LEVEL_INFO) LOG.debug(DBG_PEER_CERT + chain[0].getSubjectX500Principal().getName());
		NharuX509Certificate peer;
		if (chain[0] instanceof NharuX509Certificate) peer = (NharuX509Certificate) chain[0];
		else peer = NharuX509Factory.generateCertificate(chain[0].getEncoded());
		if (!certs.isTrusted(peer)) throw new CertificateException("Untrusted peer cert");
		if (CHECKER != null) CHECKER.getInstance().validate(peer);
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException 
	{
		if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack();
		if (authType == null || authType.length() == 0)
		{
			if (LOG_LEVEL < LOG_LEVEL_FATAL) LOG.error(ERROR_AUTH_TYPE);
			throw new IllegalArgumentException(ERROR_AUTH_TYPE);
		}
		checkTrusted(chain);
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException 
	{
		if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack();
		if (authType == null || authType.length() == 0)
		{
			if (LOG_LEVEL < LOG_LEVEL_FATAL) LOG.error(ERROR_AUTH_TYPE);
			throw new IllegalArgumentException(ERROR_AUTH_TYPE);
		}
		checkTrusted(chain);
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() 
	{
		if (issuers == null)
		{
			synchronized (this)
			{
				if (issuers == null)
				{
					issuers = new NharuX509Certificate[0];
					issuers = certs.getIssuers().toArray(issuers);
				}
			}
		}
		return issuers;
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException 
	{
		if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack();
		checkClientTrusted(chain, authType);
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException 
	{
		if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack();
		checkClientTrusted(chain, authType);
	}

	private  void checkPeerID(final SSLSession session, final String alg, final X509Certificate cert) throws CertificateException
	{
		if (session == null) throw new CertificateException("No handshake session");
		if (alg != null && !"HTTPS".equalsIgnoreCase(alg)) throw new CertificateException("Unknown identification algorithm: " + alg);
		String hostname = session.getPeerHost();
		if (hostname == null) throw new CertificateException("Hostname is not available to check");
		if (hostname.startsWith("[") && hostname.endsWith("]")) hostname = hostname.substring(1, hostname.length() - 1);
		 HostnameChecker.getInstance(HostnameChecker.TYPE_TLS).match(hostname, cert);
	}
	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException 
	{
		if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack();
		checkServerTrusted(chain, authType);
		if (ENDPOINT_VALIDATE && socket != null && socket.isConnected() && socket instanceof SSLSocket) checkPeerID(((SSLSocket) socket).getHandshakeSession(), ((SSLSocket) socket).getSSLParameters().getEndpointIdentificationAlgorithm(), chain[0]);
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException 
	{
		if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack();
		checkServerTrusted(chain, authType);
		if (ENDPOINT_VALIDATE && engine != null) checkPeerID(engine.getHandshakeSession(), engine.getSSLParameters().getEndpointIdentificationAlgorithm(), chain[0]);
	}
}
