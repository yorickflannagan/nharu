package org.crypthing.security.issue;

/**
 * Implements a Microsoft UPN Other Name
 */
public final class MicrosoftUPN extends NharuOtherName
{
	public MicrosoftUPN(final String value) { super(new int[] { 1, 3, 6, 1, 4, 1, 311, 20, 2, 3 }, value); }
}