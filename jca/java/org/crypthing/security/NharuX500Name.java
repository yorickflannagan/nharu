package org.crypthing.security;

import java.util.Arrays;
import java.util.HashMap;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * <p>X500 attributes as defined in <a href = "https://www.ietf.org/rfc/rfc2253.txt">RFC 2253</a>.
 * Only following mappings are supported:</p>
 * <pre>
 * 2.5.4.3  - id-at-commonName                  CN
 * 2.5.4.7  - id-at-localityName                L
 * 2.5.4.8  - id-at-stateOrProvinceName         ST
 * 2.5.4.10 - id-at-organizationName            O
 * 2.5.4.11 - id-at-organizationalUnitName      OU
 * 2.5.4.6  - id-at-countryName                 C
 * 2.5.4.9  - id-at-streetAddress               STREET
 * 0.9.2342.19200300.100.1.1 - userid           UID
 * 0.9.2342.19200300.100.1.25 - domainComponent DC
 * </pre>
 * @since 1.3.0
 */
public class NharuX500Name
{
	private static class Placeholder
	{
		private final int[] value;
		Placeholder(int[] value) { this.value = value; }
		@Override public int hashCode() { return Arrays.hashCode(value); }
		@Override public boolean equals(Object ano)
		{
			if (this == ano) return true;
			if (!(ano instanceof Placeholder)) return false;
			return Arrays.equals(value, ((Placeholder)ano).value);
		}
	}
	private static final int[] CN_OID		= new int[] { 2, 5, 4, 3 };
	private static final int[] L_OID		= new int[] { 2, 5, 4, 7 };
	private static final int[] ST_OID		= new int[] { 2, 5, 4, 8 };
	private static final int[] O_OID		= new int[] { 2, 5, 4, 10 };
	private static final int[] OU_OID		= new int[] { 2, 5, 4, 11 };
	private static final int[] C_OID		= new int[] { 2, 5, 4, 6 };
	private static final int[] STREET_OID	= new int[] { 2, 5, 4, 9 };
	private static final int[] UID_OID		= new int[] { 0, 9, 2342, 19200300, 100, 1, 1 };
	private static final int[] DC_OID		= new int[] { 0, 9, 2342, 19200300, 100, 1, 25 };
	private static final HashMap<String, int[]> x500Att = new HashMap<>();
	private static final HashMap<Placeholder, String> attLookup = new HashMap<>();
	static
	{
		x500Att.put("CN", CN_OID);
		x500Att.put("L", L_OID);
		x500Att.put("ST", ST_OID);
		x500Att.put("O", O_OID);
		x500Att.put("OU", OU_OID);
		x500Att.put("C", C_OID);
		x500Att.put("STREET", STREET_OID);
		x500Att.put("UID", UID_OID);
		x500Att.put("DC", DC_OID);

		attLookup.put(new Placeholder(CN_OID), "CN");
		attLookup.put(new Placeholder(L_OID), "L");
		attLookup.put(new Placeholder(ST_OID), "ST");
		attLookup.put(new Placeholder(O_OID), "O");
		attLookup.put(new Placeholder(OU_OID), "OU");
		attLookup.put(new Placeholder(C_OID), "C");
		attLookup.put(new Placeholder(STREET_OID), "STREET");
		attLookup.put(new Placeholder(UID_OID), "UID");
		attLookup.put(new Placeholder(DC_OID), "DC");
	}
	/**
	 * Parses JSON representation of a GeneralName
	 * @param json: JSON string in form  { "oid": [ 2, 5, 4, 6 ], "value": "BR" }
	 * @return an new instance
	 */
	public static NharuX500Name parseJSON(final String json)
	{
		final JSONObject ob = new JSONObject(json);
		final JSONArray oidOb = ob.getJSONArray("oid");
		int[] oid = new int[oidOb.length()];
		for (int i = 0; i < oidOb.length(); i++) oid[i] = oidOb.getInt(i);
		final Placeholder holder = new Placeholder(oid);
		if (!attLookup.containsKey(holder)) throw new IllegalArgumentException("Unrecognized X500 name");
		final NharuX500Name ret = new NharuX500Name();
		ret.oid = oid;
		ret.value = ob.getString("value");
		ret.canonical = attLookup.get(holder) + "=" + ret.value;
		return ret;
	}
	private int[] oid;
	private String value;
	private String canonical;
	private String json = null;
	private NharuX500Name() {}
	/**
	 * Creates a new instance of X500 Name.
	 * @param name: the name in form C=BR.
	 */
	public NharuX500Name(final String name)
	{
		final String[] parts = (canonical = name).split("=");
		if (parts.length != 2) throw new IllegalArgumentException("Invalid X500 Name format");
		if ((oid = x500Att.get(parts[0].trim().toUpperCase())) == null) throw new IllegalArgumentException("Unrecognized X500 name");
		value = parts[1].trim();
	}
	/**
	 * Gets the oid component of this name
	 * @return the OID itself
	 */
	public int[] getOID() { return oid; }
	/**
	 * Gets the value of this name
	 * @return the value itself.
	 */
	public String getValue() { return value; }
	/**
	 * Converts this object to its JSON representation.
	 * @return a JSON object like { "oid": [ 2, 5, 4, 3 ], "value": "Duke" }
	 */
	public String toJSON()
	{
		if (json == null)
		{
			final StringBuilder builder = new StringBuilder(128);
			builder.append("{ \"oid\": [ ");
			int i = 0;
			while (i < oid.length - 1) builder.append(oid[i++]).append(", ");
			builder.append(oid[i]).append(" ], \"value\": \"").append(value).append("\" }");
			json = builder.toString();
		}
		return json;
	}
	@Override public boolean equals(Object anoObject) { return canonical.equalsIgnoreCase(((NharuX500Name) anoObject).canonical); }
	@Override public int hashCode() { return canonical.hashCode(); }
	@Override public String toString() { return canonical; }
	@Override
	public Object clone()
	{
		final NharuX500Name ret = new NharuX500Name();
		ret.oid = Arrays.copyOf(oid, oid.length);
		ret.value = new String(value);
		ret.canonical = new String(canonical);
		return ret;
	}
}
