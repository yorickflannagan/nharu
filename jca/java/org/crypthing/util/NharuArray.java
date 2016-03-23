package org.crypthing.util;

public final class NharuArray
{
	private final byte[] internal;
	private int hash;

	public NharuArray(final byte[] array)
	{
		internal = array;
		hash = 0;
	}

	@Override
	public boolean equals(final Object o)
	{
		if (this == o) return true;
		if (!(o instanceof NharuArray)) return false;
		return NharuArrays.equals(((NharuArray) o).internal, internal);
	}

	@Override
	public int hashCode()
	{
		if (hash == 0) hash = NharuArrays.hashCode(internal); 
		return hash;
	}

	public byte[] getArray()
	{
		return internal;
	}
}
