package org.crypthing.security.x509;

public final class NharuX509Name
{
	private final String canonical;
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

	// TODO: Should implement toString() according to RFC 4514

}
