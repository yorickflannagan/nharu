package org.crypthing.security.cms;

import org.crypthing.util.NharuArrays;

/**
 * <p>Implements SignerIdentifier CMS CHOICE:</p>
 * <pre>
 * SignerIdentifier ::= CHOICE {
 * 	issuerAndSerialNumber IssuerAndSerialNumber,
 * 	subjectKeyIdentifier [0] SubjectKeyIdentifier }
 * </pre>
 * @author magut
 *
 */
public final class SignerIdentifier
{
	private final IssuerAndSerialNumber issuer;
	private final byte[] keyID;

	/**
	 * Creates a new SID instance with this IssuerAndSerialNumber.
	 * @param issuer: IssuerAndSerialNumber. Must not be null.
	 */
	public SignerIdentifier(final IssuerAndSerialNumber issuer)
	{
		if (issuer == null) throw new NullPointerException();
		this.issuer = issuer;
		keyID = null;
	}

	/**
	 * Creates a new SID instance with this SubjectKeyIdentifier
	 * @param keyID: SubjectKeyIdentifier. Must not be null.
	 */
	public SignerIdentifier(final byte[] keyID)
	{
		if (keyID == null) throw new NullPointerException();
		issuer = null;
		this.keyID = keyID;
	}

	/**
	 * Gets the IssuerAndSerialNumber CHOICE.
	 * @return IssuerAndSerialNumber or null.
	 */
	public IssuerAndSerialNumber getIssuer() { return issuer; }

	/**
	 * Gets the SubjectKeyIdentifier CHOICE.
	 * @return SubjectKeyIdentifier or null
	 */
	public byte[] getKeyID() { return keyID; }

	@Override
	public boolean equals(final Object other)
	{
		if (this == other) return true;
		if (!(other instanceof SignerIdentifier)) return false;
		final SignerIdentifier sid = (SignerIdentifier) other;
		if (issuer != null)
		{
			if (sid.issuer == null) return false;
			return issuer.equals(sid.issuer);
		}
		if (keyID != null)
		{
			if (sid.keyID == null) return false;
			return NharuArrays.equals(keyID, sid.keyID);
		}
		return false;
	}
	@Override public int hashCode()
	{
		if (issuer != null) return issuer.hashCode();
		return NharuArrays.hashCode(keyID);
	}
}
