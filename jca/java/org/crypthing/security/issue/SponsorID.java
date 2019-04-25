package org.crypthing.security.issue;

/**
 * Implements a PKI Brasil SponsorID Other Name
 */
public final class SponsorID extends NharuOtherName
{
	public SponsorID(final String value) { super(new int[] { 2, 16, 76, 1, 3, 4 }, value); }
}