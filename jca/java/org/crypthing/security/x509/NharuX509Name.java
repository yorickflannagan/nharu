package org.crypthing.security.x509;

import java.nio.charset.StandardCharsets;

/**
 * X.509 Name canonicalized as RFC 3454
 * @author magut
 *
 */
public final class NharuX509Name
{
	private final String canonical;
	private byte[] encoded;

	/**
	 * Creates a new instance with specified string
	 * @param stringprep: canonical X.509 Name
	 */
	public NharuX509Name(final String stringprep)
	{
		if (stringprep == null) throw new NullPointerException();
		canonical = stringprep;
	}
	@Override
	public boolean equals(final Object other)
	{
		if (other == null || !(other instanceof NharuX509Name)) return false;
		return canonical.equals(((NharuX509Name)other).canonical);
	}
	@Override public int hashCode() { return canonical.hashCode(); }
	@Override public String toString() { return canonical; }

	/**
	 * Gets this X.509 Name as an array of bytes.
	 * @return stringprep encoded as UTF-8.
	 */
	public byte[] getBytes() { if (encoded == null) encoded = canonical.getBytes(StandardCharsets.UTF_8); return encoded; }
}
