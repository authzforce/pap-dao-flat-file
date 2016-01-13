/**
 * Copyright (C) 2011-2014 Thales Services SAS.
 * 
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package org.ow2.authzforce.pap.dao.file;

import java.io.File;
import java.nio.charset.StandardCharsets;

import com.google.common.io.BaseEncoding;

/**
 * Utility methods
 */
public final class FileBasedDAOUtils
{
	// FIXME: Instead of google BaseEncoding, use java.util.Base64.getURLEncoder() when moving to Java 8
	private static final BaseEncoding BASE64URL_NO_PADDING_ENCODING = BaseEncoding.base64Url().omitPadding();

	/**
	 * Encode bytes with base64url specified by RFC 4648, without padding
	 * 
	 * @param bytes
	 *            input
	 * @return encoded result
	 */
	public static String base64UrlEncode(byte[] bytes)
	{
		return BASE64URL_NO_PADDING_ENCODING.encode(bytes);
	}

	/**
	 * Encode string with base64url specified by RFC 4648, without padding. Used to create filenames compatible with most filesystems
	 * 
	 * @param input
	 *            input
	 * @return encoded result
	 */
	public static String base64UrlEncode(String input)
	{
		return BASE64URL_NO_PADDING_ENCODING.encode(input.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Decode string encoded with {@link FileBasedDAOUtils#base64UrlEncode(String)}
	 * 
	 * @param encoded
	 *            input
	 * @return decoded result, i.e. original string encoded with {@link FileBasedDAOUtils#base64UrlEncode(String)}
	 * @throws IllegalArgumentException
	 *             if the input is not a valid encoded string according to base64url encoding without padding
	 */
	public static String base64UrlDecode(String encoded) throws IllegalArgumentException
	{
		return new String(BASE64URL_NO_PADDING_ENCODING.decode(encoded), StandardCharsets.UTF_8);
	}

	private static final IllegalArgumentException NULL_FILE_ARGUMENT_EXCEPTION = new IllegalArgumentException("Null file arg");

	private FileBasedDAOUtils()
	{
	}

	/**
	 * Check file access
	 * 
	 * @param friendlyname
	 *            friendly name of file for exception messages
	 * @param file
	 *            file
	 * @param isdirectory
	 *            true if and only if file is expected to be a directory
	 * @param canwrite
	 *            true if and only if file is expected to be writable
	 * @throws IllegalArgumentException
	 *             if
	 *             {@code file == null || !file.exists() || !file.canRead() || (isdirectory && !file.isDirectory()) || (!isdirectory && file.isDirectory()) || (canwrite && !file.canWrite())}
	 */
	public static void checkFile(String friendlyname, File file, boolean isdirectory, boolean canwrite) throws IllegalArgumentException
	{
		if (file == null)
		{
			throw NULL_FILE_ARGUMENT_EXCEPTION;
		}

		final String exStartMsg = friendlyname + " = '" + file.getAbsolutePath() + "' ";
		if (!file.exists())
		{
			throw new IllegalArgumentException(exStartMsg + "not found");
		}
		if (!file.canRead())
		{
			throw new IllegalArgumentException(exStartMsg + "cannot be read");
		}
		if (isdirectory && !file.isDirectory())
		{
			throw new IllegalArgumentException(exStartMsg + "is not a directory");
		}
		if (!isdirectory && file.isDirectory())
		{
			throw new IllegalArgumentException(exStartMsg + "is not a normal file");
		}
		if (canwrite && !file.canWrite())
		{
			throw new IllegalArgumentException(exStartMsg + "cannot be written to");
		}
	}

	// public static void main(String[] args)
	// {
	// String input = "mus#321=dis?lmth.xedni/DSX/moc.gnaygnoreh//:ptth";
	// // String input = "mailto:herong_yang@yahoo.com";
	//
	// System.out.println("input: " + input);
	// // FIXME: instead of google BaseEncoding, use java.util.Base64.getURLEncoder() when moving to Java 8
	// final String encodedId = BaseEncoding.base64Url().omitPadding().encode(input.getBytes(StandardCharsets.UTF_8));
	// System.out.println("Encoded base64url (without padding): " + encodedId);
	//
	// final byte[] decoded = BaseEncoding.base64Url().omitPadding().decode(encodedId);
	// System.out.println("Base64url-decoded (without padding): '" + new String(decoded, StandardCharsets.UTF_8) + "'");
	// }
}
