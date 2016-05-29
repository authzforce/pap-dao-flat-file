/**
 * Copyright (C) 2012-2016 Thales Services SAS.
 *
 * This file is part of AuthZForce CE.
 *
 * AuthZForce CE is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * AuthZForce CE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with AuthZForce CE.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.ow2.authzforce.pap.dao.flatfile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitOption;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Collections;

import com.google.common.io.BaseEncoding;

/**
 * Utility methods
 */
public final class FlatFileDAOUtils
{
	// FIXME: Instead of google BaseEncoding, use
	// java.util.Base64.getURLEncoder() when moving to Java 8
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
	 * Encode string with base64url specified by RFC 4648, without padding. Used to create filenames compatible with
	 * most filesystems
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
	 * Decode string encoded with {@link FlatFileDAOUtils#base64UrlEncode(String)}
	 * 
	 * @param encoded
	 *            input
	 * @return decoded result, i.e. original string encoded with {@link FlatFileDAOUtils#base64UrlEncode(String)}
	 * @throws IllegalArgumentException
	 *             if the input is not a valid encoded string according to base64url encoding without padding
	 */
	public static String base64UrlDecode(String encoded) throws IllegalArgumentException
	{
		return new String(BASE64URL_NO_PADDING_ENCODING.decode(encoded), StandardCharsets.UTF_8);
	}

	private static final IllegalArgumentException NULL_FILE_ARGUMENT_EXCEPTION = new IllegalArgumentException(
			"Null file arg");

	private FlatFileDAOUtils()
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
	public static void checkFile(String friendlyname, Path file, boolean isdirectory, boolean canwrite)
			throws IllegalArgumentException
	{
		if (file == null)
		{
			throw NULL_FILE_ARGUMENT_EXCEPTION;
		}

		final String exStartMsg = friendlyname + " = '" + file.toAbsolutePath() + "' ";
		if (!Files.exists(file))
		{
			throw new IllegalArgumentException(exStartMsg + "not found");
		}
		if (!Files.isReadable(file))
		{
			throw new IllegalArgumentException(exStartMsg + "cannot be read");
		}
		if (isdirectory && !Files.isDirectory(file))
		{
			throw new IllegalArgumentException(exStartMsg + "is not a directory");
		}
		if (!isdirectory && !Files.isDirectory(file))
		{
			throw new IllegalArgumentException(exStartMsg + "is not a normal file");
		}
		if (canwrite && !Files.isWritable(file))
		{
			throw new IllegalArgumentException(exStartMsg + "cannot be written to");
		}
	}

	/**
	 * Directory entry filter that accepts only regular files with a given extension/suffix
	 *
	 */
	public static final class SuffixMatchingDirectoryStreamFilter implements DirectoryStream.Filter<Path>
	{
		private final PathMatcher pathSuffixMatcher;

		/**
		 * Creates filter from a filename extension/suffix
		 * 
		 * @param suffix
		 *            filename suffix to be matched
		 */
		public SuffixMatchingDirectoryStreamFilter(String suffix)
		{
			this.pathSuffixMatcher = FileSystems.getDefault().getPathMatcher("glob:*" + suffix);
		}

		@Override
		public boolean accept(Path entry) throws IOException
		{
			final boolean isAccepted = Files.isRegularFile(entry) && Files.isReadable(entry)
					&& pathSuffixMatcher.matches(entry.getFileName());
			return isAccepted;
		}
	}

	private static class CopyingFileVisitor extends SimpleFileVisitor<Path>
	{

		private final Path source;
		private final Path target;

		private CopyingFileVisitor(Path source, Path target)
		{
			this.source = source;
			this.target = target;
		}

		@Override
		public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException
		{
			Files.copy(file, target.resolve(source.relativize(file)));
			return FileVisitResult.CONTINUE;
		}

		@Override
		public FileVisitResult preVisitDirectory(Path directory, BasicFileAttributes attributes) throws IOException
		{
			final Path targetDirectory = target.resolve(source.relativize(directory));
			try
			{
				Files.copy(directory, targetDirectory);
			} catch (FileAlreadyExistsException e)
			{
				if (!Files.isDirectory(targetDirectory))
				{
					throw e;
				}
			}
			return FileVisitResult.CONTINUE;
		}
	}

	private static FileVisitor<Path> DELETING_FILE_VISITOR = new SimpleFileVisitor<Path>()
	{
		@Override
		public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException
		{
			if (attrs.isRegularFile())
			{
				Files.delete(file);
			}

			return FileVisitResult.CONTINUE;
		}

		@Override
		public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException
		{

			if (exc == null)
			{
				Files.delete(dir);
				return FileVisitResult.CONTINUE;
			}

			throw exc;
		}
	};

	/**
	 * Copy a directory recursively to another (does not follow links)
	 * 
	 * We could use commons-io library for this, if it were using the new java.nio.file API available since Java 7, not
	 * the case so far.
	 * 
	 * @param source
	 *            source directory
	 * @param target
	 *            target directory
	 * @param maxDepth
	 *            maximum number of levels of directories to copy. A value of 0 means that only the starting directory
	 *            is visited.
	 * @throws IllegalArgumentException
	 *             if the maxDepth parameter is negative
	 * @throws IOException
	 *             file copy error
	 */
	public static void copyDirectory(Path source, Path target, int maxDepth) throws IOException,
			IllegalArgumentException
	{
		Files.walkFileTree(source, Collections.<FileVisitOption> emptySet(), maxDepth, new CopyingFileVisitor(source,
				target));
	}

	/**
	 * Delete a directory recursively
	 * 
	 * We could use commons-io library for this, if it were using the new java.nio.file API available since Java 7, not
	 * the case so far.
	 * 
	 * @param dir
	 *            directory
	 * @param maxDepth
	 *            maximum number of levels of directories to delete. A value of 0 means that only the starting file is
	 *            visited.
	 * @throws IllegalArgumentException
	 *             if the maxDepth parameter is negative
	 * @throws IOException
	 *             file deletion error
	 */
	public static void deleteDirectory(Path dir, int maxDepth) throws IOException, IllegalArgumentException
	{
		Files.walkFileTree(dir, Collections.<FileVisitOption> emptySet(), maxDepth, DELETING_FILE_VISITOR);
	}

	// public static void main(String[] args)
	// {
	// String input = "mus#321=dis?lmth.xedni/DSX/moc.gnaygnoreh//:ptth";
	// // String input = "mailto:herong_yang@yahoo.com";
	//
	// System.out.println("input: " + input);
	// // FIXME: instead of google BaseEncoding, use
	// java.util.Base64.getURLEncoder() when moving to Java 8
	// final String encodedId =
	// BaseEncoding.base64Url().omitPadding().encode(input.getBytes(StandardCharsets.UTF_8));
	// System.out.println("Encoded base64url (without padding): " + encodedId);
	//
	// final byte[] decoded =
	// BaseEncoding.base64Url().omitPadding().decode(encodedId);
	// System.out.println("Base64url-decoded (without padding): '" + new
	// String(decoded, StandardCharsets.UTF_8) + "'");
	// }
}
