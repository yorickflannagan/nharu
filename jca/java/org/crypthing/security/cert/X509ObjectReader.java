package org.crypthing.security.cert;

import java.io.IOException;

/**
 * A reader to X.509 certificates or CRLs implemented as one-way iterator.
 * @author magut
 *
 */
public interface X509ObjectReader
{
	/**
	 * Check if there are more entries to read.
	 * @return true or false.
	 */
	public boolean hasNext();

	/**
	 * Read next entry if another one exists.
	 * @return DER encoded entry.
	 * @throws IOException if entry cannot be readed.
	 */
	public byte[] readNext() throws IOException;
}
