package org.crypthing.security.crlservice;

import java.lang.management.ManagementFactory;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.management.ObjectName;

import org.crypthing.security.LogDevice;
import org.crypthing.security.crlservice.jmx.ValidatorStatus;
import org.crypthing.security.x509.NharuX509CRL;
import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.security.x509.NharuX509Name;

public final class CRLValidator {

	private static String name = "org.crypthing.security.crlservice.CRLValidator";
	static final String MBEAN_PATTERN = "org.crypthing.security.crlservice:type=CRLValidator";
	private static Random r = new Random(System.currentTimeMillis());
	private static LogDevice log = new LogDevice(name);
	static
	{
		CRLUpdater updater; 
		final String upClass = System.getProperty(name);
		if(upClass != null)
		{
			try{ (updater = (CRLUpdater) Class.forName(upClass).newInstance()).init();}
			catch(Exception e) 
			{ 
				log.error("Could not start system CRL/Certs updaters for:" + upClass, e);
				throw new ExceptionInInitializerError(e);
			}
		}
		else  
		{ 
			log.error("No updater configured for " + name);
			throw new ExceptionInInitializerError("No updater configured for " + name);
		}
		try {
			ManagementFactory.getPlatformMBeanServer().registerMBean(new ValidatorStatus(updater),new ObjectName(MBEAN_PATTERN));
		} catch (Exception e) { log.error("Could not register MBean CRLValidator.", e); }
	}
	
	private static Map<NharuX509Name, CertStatusEntry>	certsMap = new HashMap<>();
	private static long next = System.currentTimeMillis();
	private static long last;
	
	private static class CertStatusEntry
	{
		CertStatus 			status;
		NharuX509Certificate 	cert;
		CertStatusEntry 		issuer;
		NharuX509CRL		crl;
		boolean 			root;
	}	
	
	private static  CertStatus validate(final NharuX509Certificate cert, boolean checkcert)
	{
		if(cert==null) return CertStatus.INVALID;
		final CertStatusEntry issuerMap = certsMap.get(cert.getIssuer());
		if(issuerMap == null) return CertStatus.UNKNOWN_ISSUER;
		if(issuerMap.crl != null && issuerMap.crl.isRevoked(cert)) {  return CertStatus.REVOKED; }
		if(issuerMap.status != CertStatus.VALID) return issuerMap.status;
		final CertStatus status = validate(issuerMap);
		
		if(checkcert && status == CertStatus.VALID)
		{
			try
			{
				cert.checkValidity();
				cert.verify(issuerMap.cert.getPublicKey());
			}
			catch (final CertificateExpiredException e) { return CertStatus.EXPIRED; }
			catch (final CertificateNotYetValidException e) { return CertStatus.NOT_VALID_YET; }
			catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) { return CertStatus.INVALID; }
		}
		return status;
		
		
	}
		
	public static CertStatus checkCRL(final NharuX509Certificate cert)
	{
		return validate(cert, false);
	}

	public static CertStatus checkAll(final NharuX509Certificate cert)
	{
		return validate(cert, true);
	}
	
	private static CertStatus validate(CertStatusEntry entry)
	{
		while(entry != null)
		{
			if(entry.status != CertStatus.VALID) return entry.status;
			if(entry.crl == null || entry.crl.getNextUpdate().getTime() < System.currentTimeMillis()) { return CertStatus.EXPIRED_CRL; }
			if(entry.root) entry = null; else entry = entry.issuer;
		}
		return CertStatus.VALID;
	}
	
	public static void update(final NharuX509Certificate[] certs, final NharuX509CRL[] crls)
	{
		if (certs == null || crls == null) throw new NullPointerException("Arguments must not be null");
		last= System.currentTimeMillis();
		next = System.currentTimeMillis() + 60 * 60 * 1000; // 1 Hora
		final HashMap<NharuX509Name, CertStatusEntry> tmp = new HashMap<>();
		for(NharuX509Certificate c: certs)
		{
			if(c==null) throw new NullPointerException("Null certificate encountered");
			final NharuX509Name key = c.getSubject();
			final CertStatusEntry tmpentry = new CertStatusEntry();
			tmpentry.cert = c;
			tmpentry.status =  CertStatus.NOT_INITIALIZED;
			tmpentry.crl = null;
			tmpentry.issuer = null;
			tmp.put(key, tmpentry);
		}
		for(NharuX509CRL crl: crls)
		{
			final NharuX509Name key = crl.getIssuer();
			final CertStatusEntry cert = tmp.get(key);
			if (cert == null)
			{
				next = System.currentTimeMillis();
				log.warning("Certificado inexistente para CRL conhecida: "  + crl.getIssuerDN().getName());
				continue;
			}
			try { crl.verify(cert.cert.getPublicKey()); }
			catch (final InvalidKeyException | CRLException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e)
			{
				next = System.currentTimeMillis();
				log.warning("Untrusted CRL issued to "  + crl.getIssuerDN().getName());
				continue;
			}
			cert.crl = crl;
			final long v = crl.getNextUpdate().getTime() - (32000 + r.nextInt(32*1000)); //TODO: descobrir um parâmetro para este cálculo.
			if(next > v) { next = v; }
		}
		for( CertStatusEntry entry : tmp.values())
		{
			final CertStatusEntry issuer = tmp.get(entry.cert.getIssuer()); // O Cert não pode ser nulo por definição, nem o issuer atachado ao certificado.
			entry.issuer = issuer;
			if(issuer == null)
			{
				log.warning("Issuer [" + entry.cert.getIssuerDN().getName() + "] não encontrado para certificado [" + entry.cert.getSubjectDN().getName() + "]");
				entry.status = CertStatus.INVALID; continue;
			}
			
			if(issuer.cert.equals(entry.cert))  { entry.root = true; } //TODO: Root mal assinada?
			else
			{
					try {
						entry.cert.verify(issuer.cert.getPublicKey());
					} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
						entry.status = CertStatus.INVALID; continue;
					}					
					
					if(issuer.crl != null && issuer.crl.isRevoked(entry.cert.getSerialNumber().toByteArray()))
					{
						entry.status = CertStatus.REVOKED; continue;
					}
					
					try {
						entry.cert.checkValidity();
					} catch (CertificateExpiredException e) {
						entry.status = CertStatus.EXPIRED; continue;
					} catch (CertificateNotYetValidException e) {
						entry.status =CertStatus.NOT_VALID_YET; continue;
					}
					
					
					if(entry.crl == null || entry.crl.getNextUpdate().getTime() < System.currentTimeMillis())
					{
						next = System.currentTimeMillis();
						log.warning("CRL expirada para certificado: "  + entry.cert.getSubjectDN().getName());
						entry.status = CertStatus.EXPIRED_CRL; continue;
					}
			}
			entry.status = CertStatus.VALID;
		}
		// Propaga o problema de ACs superiores
		for( CertStatusEntry entry : tmp.values())
		{
			CertStatusEntry tmpentry = entry;
			while(tmpentry !=null && !tmpentry.root)
			{
				if(tmpentry.status == CertStatus.REVOKED) { entry.status = CertStatus.REVOKED; break; } 
				else if(tmpentry.status == CertStatus.INVALID) { entry.status = CertStatus.INVALID; break; }
				tmpentry = tmpentry.issuer;
			}
			if(entry.status == CertStatus.VALID) { entry.status = validate(entry);}
		}
		Map<NharuX509Name, CertStatusEntry> old = certsMap; 
		certsMap = tmp;
		// A partir daqui os certificados já estão atualizados.
		try { Thread.sleep(1000);} catch (InterruptedException e) { /* */ }
		// Espera para que deixem de usar a estrutura antiga e passem a usar a nova estrutura...
		for( CertStatusEntry entry : old.values()) { if(entry.crl != null) entry.crl.closeHandle();}
		old.clear();
	}
	
	
	public static long getLastUpdate()
	{
		return last;
	}
	
	public static long getNextUpdate()
	{
		long retorno =   next - System.currentTimeMillis();
		return retorno > 0 ? retorno : 0;
	}
	public static long getNextAsTimeMilis()
	{
		return next;
	}
	
	public static String listStatus()
	{
		String empty = "                    ";
		final Map<NharuX509Name, CertStatusEntry>	certsLocal = certsMap;
		StringBuilder sb = new StringBuilder(certsLocal.size() * 128);
		for(CertStatusEntry entry : certsLocal.values())
		{
			sb.append(entry.status.name()).append(empty.substring(0,15-entry.status.name().length())).append("\t|\t");
			if(entry.root) sb.append("(root) ");
			sb.append(entry.cert.getSubjectDN().getName());
			if(!entry.root)
			{
				sb.append("\t==>\t");
				sb.append(entry.cert.getIssuerDN().getName());
				if(entry.issuer == null) sb.append(" <NOT FOUND> ");
			}
			sb.append("\n");
		}
		return sb.toString();
	}
	
	
}