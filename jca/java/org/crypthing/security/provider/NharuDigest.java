package org.crypthing.security.provider;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;

import org.crypthing.util.NharuArrays;

/**
 * Digest implementation. It supports MD5, SHA-1, SHA-256, SHA-384 and SHA-512 mechanisms. To avoid memory leak due
 * to memory allocation during hash init, update() does not computes partial hash. It simply writes input into a 
 * memory stream. So this implementation should not be used for hash computation of very large files.  
 * @author magut
 *
 */
public abstract class NharuDigest extends MessageDigest
{
	static { NharuProvider.isLoaded(); }
	private final int hMech;
	private final ByteArrayOutputStream buffer;
	protected NharuDigest(final String algorithm, final int mechanism)
	{
		super(algorithm);
		hMech = mechanism;
		buffer = new ByteArrayOutputStream(4096);
	}
	/**
	 * Computes hash in a single pass.
	 * @param input: value to be hashed.
	 * @return the hash.
	 */
	public byte[] digestBuffer(final byte[] input) { return nhcDigest(input, hMech); }

	@Override protected void engineUpdate(byte input) { buffer.write(input); }
	@Override protected void engineUpdate(final byte[] input, final int offset, final int len) { buffer.write(input, offset, len); }
	@Override protected byte[] engineDigest() { return nhcDigest(buffer.toByteArray(), hMech); }
	@Override protected void engineReset() { buffer.reset(); }
	private static native byte[] nhcDigest(byte[] buffer, int mechanism);

	private static final int CKM_MD5 = 0x00000210;
	private static final int CKM_SHA_1 = 0x00000220;
	private static final int CKM_SHA256 = 0x00000250;
	private static final int CKM_SHA384 = 0x00000260;
	private static final int CKM_SHA512 = 0x00000270;
	private static final String MD5 = "MD5";
	private static final String SHA = "SHA";
	private static final String SHA256 = "SHA-256";
	private static final String SHA384 = "SHA-384";
	private static final String SHA512 = "SHA-512";
	public static final class MD5 extends NharuDigest { public MD5() { super(MD5, CKM_MD5); } }
	public static final class SHA extends NharuDigest { public SHA() { super(SHA, CKM_SHA_1); } }
	public static final class SHA256 extends NharuDigest { public SHA256() { super(SHA256, CKM_SHA256); } }
	public static final class SHA384 extends NharuDigest { public SHA384() { super(SHA384, CKM_SHA384); } }
	public static final class SHA512 extends NharuDigest { public SHA512() { super(SHA512, CKM_SHA512); } }



	/* * * * * * * * * * * * * * *
	 * Unit test
	 * * * * * * * * * * * * * * */
	private static final byte[] INPUT = "MESSAGETOBEHASHED".getBytes();
	private static final byte[] SHA1_HASH = "st4xP6IlU5eUG3g4ndXYTHxawHI=".getBytes();
	public static void main(final String[] args)
	{
		System.out.print("MessageDigest SHA-1 hash calculation... ");
		final NharuDigest dgst = new NharuDigest.SHA();
		if (NharuArrays.equals(NharuArrays.toBase64(dgst.digestBuffer(INPUT)), SHA1_HASH)) System.out.println("Done!");
		else System.err.println("Failed!");
	}
}
