package org.crypthing.security.auth;

import java.security.Principal;
import java.security.acl.Group;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

public final class SimpleGroup implements Group
{
	private final transient Set<Principal> principals;
	private final transient String name;

	public SimpleGroup(final String name)
	{
		principals = new HashSet<>();
		this.name = name;
	}

	@Override
	public String getName()
	{
		return name;
	}

	@Override
	public boolean addMember(final Principal user)
	{
		return principals.add(user);
	}

	@Override
	public boolean removeMember(final Principal user)
	{
		return principals.remove(user);
	}

	@Override
	public boolean isMember(final Principal member)
	{
		return principals.contains(member);
	}

	@Override
	public Enumeration<? extends Principal> members()
	{
		return Collections.enumeration(principals);
	}
}
