package org.crypthing.security;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import org.crypthing.security.provider.NharuProvider;

public class NharuRSAKeyPairGenerator extends KeyPairGenerator
{
	static { NharuProvider.isLoaded(); }
	private void writeObject(ObjectOutputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObject(java.io.ObjectInputStream stream) throws IOException { throw new NotSerializableException(); }
	private void readObjectNoData() throws ObjectStreamException { throw new NotSerializableException(); }
	private int bits = 2048;
	private long e = 65537;
	public NharuRSAKeyPairGenerator()  { super("RSA"); }
	@Override public void initialize(final int keysize) { initialize(keysize, null); }
	@Override public void initialize(final int keysize, final SecureRandom random) { try { initialize(new RSAKeyGenParameterSpec(keysize, RSAKeyGenParameterSpec.F4), random); } catch (InvalidAlgorithmParameterException e) {}}
	@Override public void initialize(final AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException { initialize(params, null); }
	@Override public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException
	{
		try
		{
			final RSAKeyGenParameterSpec args = (RSAKeyGenParameterSpec) params;
			bits = args.getKeysize();
			e = args.getPublicExponent().longValue();
			if (random != null) nharuSeedPRNG(random.generateSeed(16));
		}
		catch (Exception e) { throw new InvalidAlgorithmParameterException(e); }
	}
	@Override public KeyPair generateKeyPair()
	{
		try
		{
			final long hHandle = nharuGenerateRSAKeys(bits, e);
			try { return new KeyPair(new NharuRSAPublicKey(nharuGetPublicKey(hHandle)), new NharuRSAPrivateKey(nharuGetPrivateKey(hHandle))); }
			finally { nharuReleaseRSAKeys(hHandle); }
		}
		catch (GeneralSecurityException e) { throw new RuntimeException(e); }
	}
	private static native void nharuSeedPRNG(byte[] seed);
	private static native long nharuGenerateRSAKeys(int bits, long e) throws GeneralSecurityException;
	private static native byte[] nharuGetPrivateKey(long handle) throws EncodingException;
	private static native byte[] nharuGetPublicKey(long handle) throws EncodingException;
	private static native void nharuReleaseRSAKeys(long handle);
}