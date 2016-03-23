package org.crypthing.security.cert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.crypthing.security.x509.NharuX509Certificate;
import org.crypthing.security.x509.NharuX509Factory;
import org.crypthing.util.NharuCommon;

public class NharuCertPath extends CertPath
{
	private static final Collection<String> _encodings;
	static
	{
		List<String> list = new ArrayList<>(2);
		list.add("PkiPath");
		list.add("PKCS7");
		_encodings = Collections.unmodifiableCollection(list);
	}
	
	private final List<NharuX509Certificate> _certs;
	private byte[] _pkiEncoded = null;

	public NharuCertPath(List<? extends Certificate> certs) throws CertificateException
	{
		super("X.509");
		List<NharuX509Certificate> list = new ArrayList<>(certs.size());
		for (Certificate cert: certs)
		{
			if
			(
				cert instanceof NharuX509Certificate
			)	list.add((NharuX509Certificate) cert);
			else	list.add(NharuX509Factory.generateCertificate(cert.getEncoded()));
		}
		_certs = Collections.unmodifiableList(list);
	}
	
	@Override
	public Iterator<String> getEncodings()
	{
		return _encodings.iterator();
	}

	@Override
	public byte[] getEncoded() throws CertificateEncodingException
	{
		return encodePKIPath();
	}

	private byte[] encodePKIPath() throws CertificateEncodingException
	{
		if (_pkiEncoded == null)
		{
			final ArrayList<byte[]> list = new ArrayList<>(_certs.size());
			int size = 0;
			for (NharuX509Certificate cert: _certs)
			{
				final byte[] encoded = cert.getEncoded();
				size += encoded.length;
				list.add(encoded);
			}
			int sizeofSize = NharuCommon.getIntSize(size);
			final ByteArrayOutputStream stream = new ByteArrayOutputStream(1 + sizeofSize + size);
			stream.write(0x48);
			try
			{
				NharuCommon.writeASNInt(size, sizeofSize, stream);
				for (byte[] encode: list) stream.write(encode);
			}
			catch (final IOException e) { throw new CertificateEncodingException(e); }
			_pkiEncoded = stream.toByteArray();
		}
		return _pkiEncoded;
	}

	@Override
	public byte[] getEncoded(String encoding) throws CertificateEncodingException
	{
		if (encoding.equals("PkiPath")) return encodePKIPath();
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<? extends Certificate> getCertificates()
	{
		return _certs;
	}

}
