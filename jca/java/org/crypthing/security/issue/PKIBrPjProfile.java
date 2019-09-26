package org.crypthing.security.issue;

import java.util.ArrayList;
import java.util.Arrays;

public class PKIBrPjProfile extends UserProfile
{
	@Override public void check(final CertificateParams params) throws CertificateProfileException
	{
		ArrayList<NharuOtherName> target = new ArrayList<>();
		target.add(new SponsorID(""));
		target.add(new SponsorName(""));
		target.add(new CompanyID(("")));
		target.add(new SponsorCEI(""));
		NharuOtherName[] field = params.getSubjectAltName();
		for (int i = 0; i < target.size(); i++)
		{
			NharuOtherName name = target.get(i);
			boolean found = false;
			int j = 0;
			while (!found && j < field.length) found = Arrays.equals(name.getOID(), field[i++].getOID());
			if (!found) throw new CertificateProfileException("ICP-Brasil PJ profile must not include object " + field[i].getClass().getName()) ;
		}		
	}
}
