package org.crypthing.security.issue;

import java.util.Arrays;

import org.crypthing.util.NharuCommon;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Implements a certificate Other Name.
 * <pre>
 * OtherName ::= SEQUENCE {
 * 	type-id    OBJECT IDENTIFIER,
 * 	value      [0] EXPLICIT ANY DEFINED BY type-id }
 * </pre>
 */
public class NharuOtherName
{
	private final int[] oid;
	private final String value;
	/**
	 * Creates a new Other Name
	 * @param oid: object identifier as an array of int
	 * @param value: other name value
	 */
	public NharuOtherName(final int[] oid, final String value) { if ((this.oid = oid) == null || (this.value = value) == null) throw new IllegalArgumentException("Arguments must not be null"); }
	/**
	 * Creates a new Other Name
	 * @param oid: object identifier
	 * @param value: other name value
	 */
	public NharuOtherName(final String oid, final String value) { this(NharuCommon.stringToOID(oid), value); }
	/**
	 * Creates a new Other Name
	 * @param json: JSON object in form { "oid": [ 1, 3, 6, 1, 4, 1, 311, 20, 2, 3 ], "value": "imyself@microsofot, com" }
	 */
	public NharuOtherName(final String json)
	{
		final JSONObject ob = new JSONObject(json);
		final JSONArray array = ob.getJSONArray("oid");
		final int[] oid = new int[array.length()];
		for (int i = 0; i < array.length(); i++) oid[i] = array.getInt(i);
		this.oid = oid;
		this.value = ob.getString("value");
	}

	/**
	 * Gets Other Name object identifier
	 * @return: the OID
	 */
	public int[] getOID() { return oid; }
	/**
	 * Gets Other Name value
	 * @return: the value itself
	 */
	public String getValue() { return value; }

	@Override public int hashCode() { return Arrays.hashCode(oid) * value.hashCode(); }
	@Override public boolean equals(final Object anoObject) 
	{
		if (this == anoObject) return true;
		if (!(anoObject instanceof NharuOtherName)) return false;
		return Arrays.equals(oid, ((NharuOtherName) anoObject).getOID()) && value.equals(((NharuOtherName) anoObject).getValue());
	}
	@Override public String toString()
	{
		final StringBuilder builder = new StringBuilder(512);
		builder.append("{ \"oid\": [ ");
		int i = 0;
		while (i < oid.length - 1) builder.append(oid[i++]).append(", ");
		builder.append(oid[i]).append(" ], \"value\": \"").append(value).append("\" }");
		return builder.toString();
	}
}