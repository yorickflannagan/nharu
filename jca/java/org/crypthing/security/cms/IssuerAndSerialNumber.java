package org.crypthing.security.cms;

import org.crypthing.security.x509.NharuX509Name;
import org.crypthing.util.NharuArrays;

/**
 * Implements an RFC 3852 IssuerAndSerialNumber type
 * @author magut
 *
 */
public final class IssuerAndSerialNumber
{
	private final NharuX509Name issuer;
	private final byte[] serial;
	public IssuerAndSerialNumber(final NharuX509Name name, final byte[] serialNumber)
	{
		if (name == null || serialNumber == null || serialNumber.length == 0) throw new NullPointerException("Arguments must not be null");
		issuer = name;
		serial = serialNumber;
	}
	@Override
	public boolean equals(final Object other)
	{
		if (this == other) return true;
		if (!(other instanceof IssuerAndSerialNumber)) return false;
		return issuer.equals(((IssuerAndSerialNumber) other).getIssuer()) && NharuArrays.equals(serial, ((IssuerAndSerialNumber) other).getSerial());
	}
	@Override public int hashCode() { return issuer.hashCode() + NharuArrays.hashCode(serial); }

	/**
	 * Get the issuer part.
	 * @return the issuer.
	 */
	public NharuX509Name getIssuer() { return issuer; }

	/**
	 * Gets the serial number part.
	 * @return the serial number
	 */
	public byte[] getSerial() { return serial; }
}
