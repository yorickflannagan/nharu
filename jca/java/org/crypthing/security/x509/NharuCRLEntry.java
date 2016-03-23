package org.crypthing.security.x509;

import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CRLReason;
import java.security.cert.X509CRLEntry;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TimeZone;

import org.crypthing.util.NharuArrays;
import org.crypthing.util.NharuCommon;

public final class NharuCRLEntry extends X509CRLEntry
{
	private static native Set<int[]> nhixGetCriticalExtensionOIDs(long handle, long entryHandle);
	private static native Set<int[]> nhixGetNonCriticalExtensionOIDs(long handle, long entryHandle);
	private static native Map<int[], byte[]> nhixGetExtensions(long handle, long entryHandle);
	private static native byte[] nhixGetEncoded(long handle, long entryHandle);
	private static native byte[] nhixGetSerialNumber(long handle, long entryHandle);
	private static native long nhixGetRevocationDate(long handle, long entryHandle);


	private final Set<String> criticalExtensions;
	private final Set<String> nonCriticalExtensions;
	private final Map<String, byte[]> extensions;
	private final byte[] encoding;
	private final BigInteger serial;
	private final Date revocationDate;

	private String thisString = null;
	private int hash = 0;
	private CRLReason reason = null;
	NharuCRLEntry(final long parent, final long entryHandle)
	{
		Set<int[]> set = nhixGetCriticalExtensionOIDs(parent, entryHandle);
		Set<String> tmp;
		Iterator<int[]> it;
		if (set != null)
		{
			tmp = new HashSet<>();
			it = set.iterator();
			while (it.hasNext()) tmp.add(NharuCommon.oidToString(it.next()));
			criticalExtensions = Collections.unmodifiableSet(tmp);
		}
		else criticalExtensions = null;
		set = nhixGetNonCriticalExtensionOIDs(parent, entryHandle);
		if (set != null)
		{
			tmp = new HashSet<>();
			it = set.iterator();
			while (it.hasNext()) tmp.add(NharuCommon.oidToString(it.next()));
			nonCriticalExtensions = Collections.unmodifiableSet(tmp);
		}
		else nonCriticalExtensions = null;
		final Map<int[], byte[]> ext = nhixGetExtensions(parent, entryHandle);
		extensions = new HashMap<>();
		final Iterator<Entry<int[], byte[]>> itext = ext.entrySet().iterator();
		while (itext.hasNext())
		{
			final Entry<int[], byte[]> entry = itext.next();
			extensions.put(NharuCommon.oidToString(entry.getKey()), entry.getValue());
		}
		encoding = nhixGetEncoded(parent, entryHandle);
		serial = new BigInteger(nhixGetSerialNumber(parent, entryHandle));
		final Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
		cal.setTimeInMillis(nhixGetRevocationDate(parent, entryHandle));
		revocationDate = cal.getTime();
	}


	/*
	 * * * * * * * * * * * * * * * * * * * * * * * * *
	 * java.security.cert.X509Extension implementation
	 * * * * * * * * * * * * * * * * * * * * * * * * *
	 */
	@Override public boolean hasUnsupportedCriticalExtension() { return false; }
	@Override public Set<String> getCriticalExtensionOIDs() { return criticalExtensions; }
	@Override public Set<String> getNonCriticalExtensionOIDs() { return nonCriticalExtensions; }
	@Override
	public byte[] getExtensionValue(final String oid)
	{
		if (oid == null) throw new NullPointerException("Argument oid must not be null.");
		return extensions.get(oid);
	}


	/*
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 * java.security.cert.X509CRLEntry abstract methods implementation
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 */
	@Override public byte[] getEncoded() throws CRLException { return encoding; }
	@Override public BigInteger getSerialNumber() { return serial; }
	@Override public Date getRevocationDate() { return revocationDate; }
	@Override public boolean hasExtensions() { return extensions.size() > 0; }
	@Override
	public String toString()
	{
		if (thisString == null)
		{
			final StringBuilder builder = new StringBuilder(512);
			builder.append("The certificate of serial number ");
			builder.append(getSerialNumber().toString());
			builder.append(" was revoked at ");
			builder.append(getRevocationDate().toString());
			thisString = builder.toString();
		}
		return thisString;
	}

	/*
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 * java.security.cert.X509CRLEntry non-abstract methods implementation
	 * This shit also has circular dependencies
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 */
	@Override
	public boolean equals(final Object other)
	{
		if (this == other) return true;
		if (!(other instanceof NharuCRLEntry)) return false;
		try { return NharuArrays.equals(getEncoded(), ((NharuCRLEntry) other).getEncoded()); }
		catch (final CRLException e) { return false; }
	}

	@Override
	public int hashCode()
	{	
		if (hash == 0)
		try { hash = NharuArrays.hashCode(getEncoded()); }
		catch (final CRLException e) { /* swalloed */ }
		return hash;
	}

	private static final String CRLReasonOID = "2.5.29.21";
	private static final CRLReason[] reasons =
	{
		CRLReason.UNSPECIFIED,
		CRLReason.KEY_COMPROMISE,
		CRLReason.CA_COMPROMISE,
		CRLReason.AFFILIATION_CHANGED,
		CRLReason.SUPERSEDED,
		CRLReason.CESSATION_OF_OPERATION,
		CRLReason.CERTIFICATE_HOLD,
		null,
		CRLReason.REMOVE_FROM_CRL,
		CRLReason.PRIVILEGE_WITHDRAWN,
		CRLReason.AA_COMPROMISE
	};
	@Override
	public CRLReason getRevocationReason()
	{
		if (reason == null)
		{
			final byte[] value = getExtensionValue(CRLReasonOID);
			int reasonIdx = 7;
			if (value != null && value.length == 3 && value[0] == 0x0A && value[2] >= 0 && value[2] < reasons.length ) reasonIdx = value[2];
			reason = reasons[reasonIdx];
		}
		return reason;
	}
}
