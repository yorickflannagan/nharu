package org.crypthing.security.issue;

/**
 * Implements a PKI Brasil CompanyID Other Name
 */
public final class CompanyID extends NharuOtherName
{
	public CompanyID(final String value) { super(new int[] { 2, 16, 76, 1, 3, 3 }, value); }
}