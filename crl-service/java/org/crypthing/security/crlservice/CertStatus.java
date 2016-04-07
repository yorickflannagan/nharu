package org.crypthing.security.crlservice;

public enum CertStatus {
		VALID(0),
		REVOKED(1),
		EXPIRED_CRL(2),
		UNKNOWN_ISSUER(3),
		EXPIRED(4),
		NOT_VALID_YET(5),
		NOT_INITIALIZED(6),
		INVALID(7);
		
		
		
		private int value;

		private CertStatus(int value)
		{
			this.value = value;
		}
		
		public static CertStatus getByValue(int value)
		{
			switch (value)
			{
				case 0: return VALID;
				case 1: return REVOKED;
				case 2: return EXPIRED_CRL;
				case 3: return UNKNOWN_ISSUER;
				case 4: return EXPIRED;
				case 5: return NOT_VALID_YET;
				case 6: return NOT_INITIALIZED;
				case 7: return INVALID;
				
				default:
					throw new RuntimeException();
			}
			
		}
		public int getValue()
		{
			return value;
		}
}
