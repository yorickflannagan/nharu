package org.crypthing.security.issue;

/**
 * Implements a PKI Brazil SubjectID Other Name
 */
public final class SubjectID extends NharuOtherName
{
	public SubjectID(final String value) { super(new int[] { 2, 16, 76, 1, 3, 1 }, value); }
}