package org.crypthing.security.auth.spi;

import java.io.IOException;
import java.security.Principal;
import java.security.acl.Group;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;

import org.crypthing.security.LogDevice;
import org.crypthing.security.auth.SimpleGroup;
import org.crypthing.security.auth.X509Identity;
import org.crypthing.security.crlservice.CRLValidator;
import org.crypthing.security.crlservice.CertStatus;
import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.security.x509.NharuX509Factory;

import static org.crypthing.security.LogDevice.LOG_LEVEL;
import static org.crypthing.security.LogDevice.LOG_LEVEL_TRACE;
import static org.crypthing.security.LogDevice.LOG_LEVEL_DEBUG;

import org.jboss.security.auth.callback.ObjectCallback;

@SuppressWarnings({ "unchecked", "unused" })
public class LocalCRLCheckerLoginModule implements LoginModule
{

	private static final String CRLCHECKER_LENIENT_ENTRY = "org.crypthing.security.auth.LoginModule.acceptExpiredCRL";

	private static final String ERROR_SSL_REQUIRED = "Login requires an embbeded X.509 certificate";
	private static final String ERROR_CRL_CHECK_ERROR = "Could not check peer certificate revocation";
	private static final String ERROR_MODULE_FAILURE = "Authenticated identitity has been released";
	private static final String ERROR_MODULE_ABORT_FAILURE = "Could not remove identity from subject";
	private static final String ERROR_NO_CALLBACK_HANDLER = "No CallbackHandler available to collect authentication information";
	private static final String MSG_LOGIN_FAILED = "CRL of [_ISSUER_] verification failed for certificate issued to [_SUBJECT_] with serial number [_SERIAL_] with status [_STATUS_]";
	private static final String MSG_LOGIN_ACCEPTED = "Certificate issued to [_SUBJECT_] has been verified with status [_STATUS_]";
	private static final String MSG_COMMIT = "Identity of [_SUBJECT_] added to subject";
	private static final LogDevice LOG = new LogDevice(LocalCRLCheckerLoginModule.class.getName());

	
	private static final String REQUEST_X509_ATTRIBUTE = "javax.servlet.request.X509Certificate";
	private static final String JBOSS_IDENTITY = "CallerPrincipal";	// Required by JBoss
	private static final String SERVLET_REQUEST = HttpServletRequest.class.getName();
	private static final String CRLCHECKER_IDENTITY_ENTRY = "org.crypthing.security.auth.LoginModule.X509Identity";
	private transient Subject subject;
	private transient Map<String, Object> sharedState; 
	private transient Map<String, String> options;
	private transient boolean loginOK = false;
	private transient X509Identity identity = null;
	private transient Group thePrincipal = null;				// Required by JBoss
	private transient CallbackHandler callbackHandler;

	@Override
	public void initialize
	(
		Subject subj,
		CallbackHandler callback,
		Map<String, ?> shared,
		Map<String, ?> opt
	)
	{
		this.subject = subj;
		this.options = (Map<String, String>) opt;
		this.sharedState = (Map<String, Object>) shared;
		this.callbackHandler = callback; 
		if (LOG_LEVEL <= LOG_LEVEL_TRACE)
		{
			final StringBuilder builder = new StringBuilder();
			final Iterator<?> it = this.options.entrySet().iterator();
			builder.append("initialize\n");
			while (it.hasNext())
			{
				final Map.Entry<String, String> item = (Entry<String, String>) it.next();
				builder.append(item.getKey());
				builder.append(" = ");
				builder.append(item.getValue());
				builder.append("\n");
			}
			LOG.trace(builder.toString());
		}
	}

	@Override
	public boolean login() throws LoginException
	{
		if (LOG_LEVEL <= LOG_LEVEL_TRACE) LOG.trace("login");
		try
		{
			if (callbackHandler == null) { throw new LoginException(ERROR_NO_CALLBACK_HANDLER); }			
			ObjectCallback oc = new ObjectCallback("Certificate: ");
			Callback[] callbacks = { oc };
			final Object reqAttr;
			callbackHandler.handle(callbacks);
			reqAttr = oc.getCredential();
			X509Certificate credentials;
			if (reqAttr instanceof X509Certificate[]) credentials = ((X509Certificate[])reqAttr)[0];
			else if (reqAttr instanceof X509Certificate) credentials = (X509Certificate) reqAttr;
			else { throw new LoginException(ERROR_SSL_REQUIRED); }
			if(!(credentials instanceof NharuX509Certificate)) credentials = NharuX509Factory.generateCertificate(credentials.getEncoded());
			final CertStatus status = CRLValidator.checkCRL((NharuX509Certificate) credentials);
			if
			(
				status != CertStatus.VALID &&
				!(
					status == CertStatus.EXPIRED_CRL &&
					Boolean.parseBoolean(options.get(CRLCHECKER_LENIENT_ENTRY))
				)
			)
			{
				if
				(
					LOG_LEVEL <= LOG_LEVEL_DEBUG
				)	LOG.debug
					(
						MSG_LOGIN_FAILED.replace
						(
							"[_ISSUER_]",
							credentials.getIssuerX500Principal().getName()
						).replace
						(
							"[_SUBJECT_]",
							credentials.getSubjectX500Principal().getName()
						).replace
						(
							" [_SERIAL_]",
							credentials.getSerialNumber().toString()
						).replace
						(
							"[_STATUS_]",
							status.toString()
						)
					);
				throw new FailedLoginException();
			}
			if (identity != null ) identity.getParser().releaseParser();
			identity = new X509Identity((NharuX509Certificate) credentials, status);
				
			loginOK = true;
			if
			(
				LOG_LEVEL <= LOG_LEVEL_TRACE
			)	LOG.trace
				(
					MSG_LOGIN_ACCEPTED.replace
					(
						"[_SUBJECT_]",
						credentials.getSubjectX500Principal().getName()
					).replace
					(
						"[_STATUS_]",
						status.toString()
					)
				);
		}
		catch ( Exception e)
		{
			LoginException ex = new LoginException(ERROR_CRL_CHECK_ERROR);
			ex.initCause(e);
			LOG.error(ERROR_CRL_CHECK_ERROR, ex);
			throw ex;
		}
		return loginOK;
	}

	@Override
	public boolean commit() throws LoginException
	{
		if (LOG_LEVEL <= LOG_LEVEL_TRACE) LOG.trace("commit");
		if (loginOK)
		{
			if
			(
				identity == null
			)
			{
				LOG.error(ERROR_MODULE_FAILURE);
				throw new LoginException(ERROR_MODULE_FAILURE);
			}
			if
			(
				(thePrincipal = getJBossPrincipal()) == null
			)	thePrincipal = new SimpleGroup(JBOSS_IDENTITY);
			else	thePrincipal.removeMember(identity);
			thePrincipal.addMember(identity);
			subject.getPrincipals().add(identity);
			subject.getPrincipals().add(thePrincipal);
			sharedState.put(CRLCHECKER_IDENTITY_ENTRY, identity);
			if
			(
				LOG_LEVEL <= LOG_LEVEL_DEBUG
			)	LOG.debug(MSG_COMMIT.replace("[_SUBJECT_]", identity.getName()));
		}
		return loginOK;
	}

	@Override
	public boolean abort() throws LoginException
	{
		if (loginOK) removeIdentity();
		return loginOK;
	}

	@Override
	public boolean logout() throws LoginException
	{
		if (LOG_LEVEL <= LOG_LEVEL_TRACE) LOG.trace("logout");
		removeIdentity();
		return true;
	}

	@Override
	public Object clone() throws CloneNotSupportedException { throw new CloneNotSupportedException(); }


	private Group getJBossPrincipal()
	{
		
		Group ret = null;
		final Iterator<Principal> it = subject.getPrincipals().iterator();
		while (it.hasNext() && ret == null)
		{
			final Principal i = it.next();
			if
			(
				i instanceof Group &&
				i.getName().equalsIgnoreCase(JBOSS_IDENTITY)
			)	ret = (Group)i;
		}
		return ret;
	}
	private void removeIdentity() throws LoginException
	{
		if (identity != null)
		{
			if
			(
				subject.getPrincipals().contains(identity) &&
				!subject.isReadOnly()
			)	subject.getPrincipals().remove(identity);
			try { identity.getParser().releaseParser(); }
			catch (final CertificateException e)
			{
				final LoginException ex = new LoginException();
				ex.initCause(e);
				LOG.error(ERROR_MODULE_ABORT_FAILURE, ex);
				throw ex;
			}
		}
		if
		(
			thePrincipal != null &&
			subject.getPrincipals().contains(thePrincipal) &&
			!subject.isReadOnly()
		)	subject.getPrincipals().remove(thePrincipal);
		identity = null;
		thePrincipal = null;
	}
}
