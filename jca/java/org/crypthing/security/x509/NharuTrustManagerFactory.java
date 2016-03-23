package org.crypthing.security.x509;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;

import org.crypthing.security.LogDevice;

import static org.crypthing.security.LogDevice.LOG_LEVEL;
import static org.crypthing.security.LogDevice.LOG_LEVEL_DEBUG;

/**
 * <h>TrustManagerFactorySpi implementation</h>
 * <p>X509ExtendedTrustManager configuration entries:</p>
 * <ul>
 * <li>org.crypthing.security.x509.CRLCheckerFactory: Check if certificate chain is not revoked. Default: null</li>
 * <li>org.crypthing.security.x509.PeerAddressValidate: validate endpoint address against peer certificate. Default: false</li>
 * </ul>
 * 
 * @author yorick.flannagan@gmail.com & diego.sohsten@globo.com
 *
 */
public class NharuTrustManagerFactory  extends TrustManagerFactorySpi
{
	private static final LogDevice LOG = new LogDevice(NharuTrustManagerFactory.class.getName());

	NharuTrustManager[] tm = new NharuTrustManager[1];
	boolean init = false;
	
	
	@Override
	public TrustManager[] engineGetTrustManagers()
	{
		if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack();
		if (!init) throw new IllegalStateException();
		return tm;
	}

	@Override
	public void engineInit(final KeyStore ks) throws KeyStoreException
	{
		if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack();
		tm[0] = new NharuTrustManager(ks);
		init = true;
	}

	@Override
	public void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException
	{
		if (LOG_LEVEL < LOG_LEVEL_DEBUG) LOG.printStack();
		//TODO: engineInit ManagerFactoryParameters
	}

}
