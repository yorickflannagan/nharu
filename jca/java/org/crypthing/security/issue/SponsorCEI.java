package org.crypthing.security.issue;

/**
 * Implements a PKI Brasil SponsorCEI Other Name
 */
public final class SponsorCEI extends NharuOtherName
{
	public SponsorCEI(final String value) { super(new int[]{ 2, 16, 76, 1, 3, 7 }, value); }
}