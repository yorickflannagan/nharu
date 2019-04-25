package org.crypthing.security.issue;

/**
 * Implements a PKI Brasil SubjectCEI Other Name
 */
public final class SubjectCEI extends NharuOtherName
{
	public SubjectCEI(final String value) { super(new int[] { 2, 16, 76, 1, 3, 6 }, value); }
}