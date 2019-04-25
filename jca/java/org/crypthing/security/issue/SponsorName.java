package org.crypthing.security.issue;

/**
 * Implements a PKI Brasil SponsorName Other Name
 */
public final class SponsorName extends NharuOtherName
{
	public SponsorName(final String value) { super(new int[]{ 2, 16, 76, 1, 3, 2 }, value); }
}