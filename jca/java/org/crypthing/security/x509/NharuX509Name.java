package org.crypthing.security.x509;

import org.crypthing.security.provider.NharuProvider;

public final class NharuX509Name
{
	static { NharuProvider.isLoaded(); }

	private final NativeParent parent;
	private final NativeParent.X509FieldName node;

	private int hash = 0;
	NharuX509Name(final NativeParent parent, final NharuX509Certificate.X509FieldName node)
	{
		this.parent = parent;
		this.node = node;
	}

	@Override
	public boolean equals(final Object other)
	{
		if (this == other) return true;
		if (!(other instanceof NharuX509Name)) return false;
		return nhixMatchName(parent.getParentHandle(node), ((NharuX509Name) other).getNameHandle());
	}

	@Override
	public int hashCode()
	{
		if (hash == 0) hash = nhixGetNameHash(parent.getParentHandle(node));
		return hash;
	}

	public long getNameHandle()
	{
		return parent.getParentHandle(node);
	}

	private static native boolean nhixMatchName(long aHandle, long bHandle);
	private static native int nhixGetNameHash(long handle);


	// TODO: Should implement toString() according to RFC 4514

}
