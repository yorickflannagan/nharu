package org.crypthing.security.cert;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.NoSuchElementException;

/**
 * Implements a directory X.509 objects reader. All directory entries are read.
 * It is expected that only certificates or CRLs exists in the source directory.
 * The X.509 object files may be DER or PEM encoded. 
 * @author magut
 *
 */
public final class X509DirectoryReader implements X509CertificateReader, X509CRLReader
{
	private static final int BLOCK_SIZE = 32768;
	private static final int BUFFER_SIZE = 4096;

	private final File[] list;
	private int current;
	private int size;

	public X509DirectoryReader(final File folder)
	{
		list = folder.listFiles();
		current = 0;
		size = list != null ? list.length : 0;
	}

	@Override
	public boolean hasNext()
	{
		return (current < size);
	}

	@Override
	public byte[] readNext() throws IOException
	{
		if (!hasNext()) throw new NoSuchElementException();
		byte[] ret = null;
		final FileInputStream in = new FileInputStream(list[current++]);
		try
		{
			final ByteArrayOutputStream out = new ByteArrayOutputStream(BLOCK_SIZE);
			final byte[] buffer = new byte[BUFFER_SIZE];
			int read;
			while ((read = in.read(buffer, 0, BUFFER_SIZE)) != -1) out.write(buffer, 0, read);
			ret = out.toByteArray();
		}
		finally { in.close(); }
		return ret;
	}
}
