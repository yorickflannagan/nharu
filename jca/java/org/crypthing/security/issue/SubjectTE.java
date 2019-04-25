package org.crypthing.security.issue;

/**
 * Implements a PKI Brasil SubjectTE Other Name
 */
public final class SubjectTE extends NharuOtherName
{
	public SubjectTE(final String  value) { super(new int[] { 2, 16, 76, 1, 3, 5 }, value); }
}