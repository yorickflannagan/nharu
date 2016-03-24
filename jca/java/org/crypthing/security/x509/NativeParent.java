package org.crypthing.security.x509;

public interface NativeParent
{
	enum X509FieldName
	{
		ISSUER,
		SUBJECT;
	}
	long getParentHandle(X509FieldName node);
}
