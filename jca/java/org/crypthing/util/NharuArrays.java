package org.crypthing.util;

import java.util.Arrays;
import java.util.HashSet;

import org.crypthing.security.provider.NharuProvider;

public class NharuArrays
{
	static { NharuProvider.isLoaded(); }

	
	private static native boolean nhIsEquals(byte[] a, byte[] b);
	private static native int nhGetHashCode(byte[] a);
	private static native byte[] nhFromBase64(byte[] encoding);
	private static native byte[] nhToBase64(byte[] data);

	public static boolean equals(final byte[] a, final byte[] b)
	{
		if (a == null && b == null) return true;
		if (a == null || b == null) return false;
		return nhIsEquals(a, b);
	}

	public static int hashCode(final byte[] a)
	{
		if (a == null) return 0;
		return nhGetHashCode(a);
	}

	public static byte[] fromBase64(final byte[] encoding)
	{
		if (encoding == null) throw new NullPointerException();
		return nhFromBase64(encoding);
	}

	public static byte[] toBase64(final byte[] data)
	{
		if (data == null) throw new NullPointerException();
		final byte[] b64 = nhToBase64(data);
		if (b64.length < 73) return Arrays.copyOf(b64, b64.length - 1);
		return b64;
	}



	/*
	 * Basic tests
	 * ==================================
	 */
	private static final byte[] ANAME =
	{
		0x30, 0x72, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x42, 0x52, 0x31, 
		0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0A, 0x50, 0x4B, 0x49, 0x20, 0x42, 0x72, 
		0x61, 0x7A, 0x69, 0x6C, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x16, 0x50, 
		0x4B, 0x49, 0x20, 0x52, 0x75, 0x6C, 0x65, 0x72, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x41, 0x6C, 0x6C, 
		0x20, 0x43, 0x61, 0x74, 0x73, 0x31, 0x2D, 0x30, 0x2B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x24, 
		0x43, 0x6F, 0x6D, 0x6D, 0x6F, 0x6E, 0x20, 0x4E, 0x61, 0x6D, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x20, 
		0x41, 0x6C, 0x6C, 0x20, 0x43, 0x61, 0x74, 0x73, 0x20, 0x45, 0x6E, 0x64, 0x20, 0x55, 0x73, 0x65, 
		0x72, 0x20, 0x43, 0x41
	};
	public static void main(final String[] args)
	{
		HashSet<NharuArray> set = new HashSet<>();
		set.add(new NharuArray(ANAME));
		if (!set.contains(new NharuArray(ANAME))) throw new RuntimeException("Hash code and equals test failed for NharuArrays");
		if (!NharuArrays.equals(ANAME, NharuArrays.fromBase64(NharuArrays.toBase64(ANAME)))) throw new RuntimeException("Base64 conversion failed for NharuArrays");
		System.out.println("NharuArrays test succeeded");
	}
}
