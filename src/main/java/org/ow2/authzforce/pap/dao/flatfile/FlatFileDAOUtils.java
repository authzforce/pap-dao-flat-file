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
import java.net.MalformedURLException;
import java.net.URL;
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
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Collections;
import java.util.Map;
import java.util.Map.Entry;

import javax.xml.bind.JAXBException;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.PolicySet;

import org.ow2.authzforce.core.pdp.api.JaxbXACMLUtils;
import org.ow2.authzforce.core.pdp.api.XMLUtils.NamespaceFilteringParser;
import org.ow2.authzforce.core.pdp.api.XMLUtils.NoNamespaceFilteringParser;
import org.ow2.authzforce.core.pdp.api.policy.PolicyVersion;
import org.ow2.authzforce.core.pdp.impl.policy.PolicyVersions;

import com.google.common.base.Preconditions;
import com.google.common.io.BaseEncoding;
import com.koloboke.collect.map.hash.HashObjObjMaps;

/**
 * Utility methods
 */
public final class FlatFileDAOUtils
{
	// FIXME: Instead of google BaseEncoding, use
	// java.util.Base64.getURLEncoder() when moving to Java 8
	private static final BaseEncoding BASE64URL_NO_PADDING_ENCODING = BaseEncoding.base64Url().omitPadding();

	private static final IllegalArgumentException NULL_FILE_ARGUMENT_EXCEPTION = new IllegalArgumentException("Null file arg");

	/**
	 * Encode bytes with base64url specified by RFC 4648, without padding
	 * 
	 * @param bytes
	 *            input
	 * @return encoded result
	 */
	public static String base64UrlEncode(final byte[] bytes)
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
	public static String base64UrlEncode(final String input)
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
	public static String base64UrlDecode(final String encoded) throws IllegalArgumentException
	{
		return new String(BASE64URL_NO_PADDING_ENCODING.decode(encoded), StandardCharsets.UTF_8);
	}

	/**
	 * Get part of filename before given suffix
	 * 
	 * @param file
	 *            path
	 * @param filenameSuffixLength
	 *            length of the suffix
	 * @return prefix
	 * @throws IllegalArgumentException
	 *             file has no filename (probably root of filesystem)
	 */
	public static String getPrefix(final Path file, final int filenameSuffixLength) throws IllegalArgumentException
	{
		assert file != null;

		final Path fileName = file.getFileName();
		if (fileName == null)
		{
			throw new IllegalArgumentException("Invalid file (no filename, probably root?): " + file);
		}

		final String filename = fileName.toString();
		return filename.substring(0, filename.length() - filenameSuffixLength);

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
	 *             if {@code file == null || !file.exists() || !file.canRead() || (isdirectory && !file.isDirectory()) || (!isdirectory && file.isDirectory()) || (canwrite && !file.canWrite())}
	 */
	public static void checkFile(final String friendlyname, final Path file, final boolean isdirectory, final boolean canwrite) throws IllegalArgumentException
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
	 * Directory entry filter that accepts only sub-directories
	 *
	 */
	public static final DirectoryStream.Filter<Path> SUB_DIRECTORY_STREAM_FILTER = new DirectoryStream.Filter<Path>()
	{

		@Override
		public boolean accept(final Path entry) throws IOException
		{
			return Files.isDirectory(entry);
		}
	};

	/**
	 * Directory entry filter that accepts only regular files with a given extension/suffix
	 *
	 */
	public static final class SuffixMatchingDirectoryStreamFilter implements DirectoryStream.Filter<Path>
	{
		private final PathMatcher pathSuffixMatcher;
		private final String pathSuffix;

		/**
		 * Creates filter from a filename extension/suffix
		 * 
		 * @param suffix
		 *            filename suffix to be matched
		 */
		public SuffixMatchingDirectoryStreamFilter(final String suffix)
		{
			this.pathSuffix = suffix;
			this.pathSuffixMatcher = FileSystems.getDefault().getPathMatcher("glob:*" + suffix);
		}

		/**
		 * Get the filename suffix used for filtering
		 * 
		 * @return the matched filename suffix
		 */
		public String getMatchedSuffix()
		{
			return this.pathSuffix;
		}

		@Override
		public boolean accept(final Path entry) throws IOException
		{
			return Files.isRegularFile(entry) && pathSuffixMatcher.matches(entry.getFileName());
		}
	}

	private static class CopyingFileVisitor extends SimpleFileVisitor<Path>
	{

		private final Path source;
		private final Path target;

		private CopyingFileVisitor(final Path source, final Path target)
		{
			this.source = source;
			this.target = target;
		}

		@Override
		public FileVisitResult visitFile(final Path file, final BasicFileAttributes attributes) throws IOException
		{
			Files.copy(file, target.resolve(source.relativize(file)));
			return FileVisitResult.CONTINUE;
		}

		@Override
		public FileVisitResult preVisitDirectory(final Path directory, final BasicFileAttributes attributes) throws IOException
		{
			final Path targetDirectory = target.resolve(source.relativize(directory));
			try
			{
				Files.copy(directory, targetDirectory);
			}
			catch (final FileAlreadyExistsException e)
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
		public FileVisitResult visitFile(final Path file, final BasicFileAttributes attrs) throws IOException
		{
			if (attrs.isRegularFile())
			{
				Files.delete(file);
			}

			return FileVisitResult.CONTINUE;
		}

		@Override
		public FileVisitResult postVisitDirectory(final Path dir, final IOException exc) throws IOException
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
	 * We could use commons-io library for this, if it were using the new java.nio.file API available since Java 7, not the case so far.
	 * 
	 * @param source
	 *            source directory
	 * @param target
	 *            target directory
	 * @param maxDepth
	 *            maximum number of levels of directories to copy. A value of 0 means that only the starting directory is visited.
	 * @throws IllegalArgumentException
	 *             if the maxDepth parameter is negative
	 * @throws IOException
	 *             file copy error
	 */
	public static void copyDirectory(final Path source, final Path target, final int maxDepth) throws IOException, IllegalArgumentException
	{
		Files.walkFileTree(source, Collections.<FileVisitOption> emptySet(), maxDepth, new CopyingFileVisitor(source, target));
	}

	/**
	 * Delete a directory recursively
	 * 
	 * We could use commons-io library for this, if it were using the new java.nio.file API available since Java 7, not the case so far.
	 * 
	 * @param dir
	 *            directory
	 * @param maxDepth
	 *            maximum number of levels of directories to delete. A value of 0 means that only the starting file is visited.
	 * @throws IllegalArgumentException
	 *             if the maxDepth parameter is negative
	 * @throws IOException
	 *             file deletion error
	 */
	public static void deleteDirectory(final Path dir, final int maxDepth) throws IOException, IllegalArgumentException
	{
		Files.walkFileTree(dir, Collections.<FileVisitOption> emptySet(), maxDepth, DELETING_FILE_VISITOR);
	}

	/**
	 * Get/load policy from file
	 * 
	 * @param policyFilepath
	 *            policy file
	 * @param xacmlParser
	 *            XACML parser; or null if the default should be used (same as {@link #loadPolicy(Path)})
	 * @return JAXB-annotated XACML PolicySet
	 * @throws IllegalArgumentException
	 *             if {@code policyFilepath} does not exist or the file content is not a PolicySet
	 * @throws JAXBException
	 *             error parsing XACML policy file into JAXB PolicySet
	 */
	public static PolicySet loadPolicy(final Path policyFilepath, final NamespaceFilteringParser xacmlParser) throws IllegalArgumentException, JAXBException
	{
		final URL policyURL;
		try
		{
			policyURL = Preconditions.checkNotNull(policyFilepath, "Undefined policyFilepath").toUri().toURL();
		}
		catch (final MalformedURLException e)
		{
			throw new IllegalArgumentException("Failed to locate policy file: " + policyFilepath, e);
		}

		final NamespaceFilteringParser nonNullXacmlParser = xacmlParser == null ? new NoNamespaceFilteringParser(JaxbXACMLUtils.createXacml3Unmarshaller()) : xacmlParser;
		final Object jaxbPolicyOrPolicySetObj;
		try
		{
			jaxbPolicyOrPolicySetObj = nonNullXacmlParser.parse(policyURL);
		}
		catch (final JAXBException e)
		{
			throw new JAXBException("Failed to unmarshall Policy(Set) XML document from policy location: " + policyURL, e);
		}

		/*
		 * If jaxbPolicyOrPolicySetObj == null, instanceof returns false, so the exception is thrown
		 */
		if (!(jaxbPolicyOrPolicySetObj instanceof PolicySet))
		{
			throw new IllegalArgumentException("Unexpected/unsupported element found as root of the XML document at policy location '" + policyURL + "': "
					+ jaxbPolicyOrPolicySetObj.getClass().getSimpleName());

		}

		return (PolicySet) jaxbPolicyOrPolicySetObj;
	}

	/**
	 * Get/load policy from file
	 * 
	 * @param policyFilepath
	 *            policy file
	 * @return JAXB-annotated XACML PolicySet
	 * @throws IllegalArgumentException
	 *             if {@code policyFilepath} does not exist or the file content is not a PolicySet
	 * @throws JAXBException
	 *             error parsing XACML policy file into JAXB PolicySet
	 */
	public static PolicySet loadPolicy(final Path policyFilepath) throws IllegalArgumentException, JAXBException
	{
		return loadPolicy(policyFilepath, null);
	}

	/**
	 * Get latest version and corresponding file path of a Policy(Set) document in a directory where each file is named '${version}suffix' representing a specific XACML Policy(Set) Version
	 * (${version}) of this document
	 * 
	 * @param versionsDirectory
	 *            directory containing the Policy(Set) version files
	 * @param filenameSuffixMatchingFilter
	 *            file filter that accepts only policy filenames with a specific suffix (e.g. '.xml')
	 * @return latest version
	 * @throws IOException
	 *             error Error listing files in {@code versionsDirectory}
	 * @throws NullPointerException
	 *             if {@code versionsDirectory == null}
	 */
	public static Entry<PolicyVersion, Path> getLatestPolicyVersion(final Path versionsDirectory, final SuffixMatchingDirectoryStreamFilter filenameSuffixMatchingFilter) throws IOException
	{
		try (final DirectoryStream<Path> policyDirStream = Files.newDirectoryStream(Preconditions.checkNotNull(versionsDirectory, "Undefined versionsDirectory"),
				Preconditions.checkNotNull(filenameSuffixMatchingFilter, "Undefined filenameSuffixMatchingFilter")))
		{
			PolicyVersion latestVersion = null;
			Path latestFilepath = null;
			for (final Path policyVersionFilePath : policyDirStream)
			{
				final Path policyVersionFileName = policyVersionFilePath.getFileName();
				if (policyVersionFileName == null)
				{
					throw new IOException("Invalid policy file path: " + policyVersionFilePath);
				}

				final String versionPlusSuffix = policyVersionFileName.toString();
				final String versionId = versionPlusSuffix.substring(0, versionPlusSuffix.length() - filenameSuffixMatchingFilter.pathSuffix.length());
				final PolicyVersion version = new PolicyVersion(versionId);
				if (latestVersion == null || latestVersion.compareTo(version) < 0)
				{
					latestVersion = version;
					latestFilepath = policyVersionFilePath;
				}
			}
			return new SimpleImmutableEntry<>(latestVersion, latestFilepath);
		}
		catch (final IOException e)
		{
			throw e;
		}
	}

	/**
	 * Get versions of a Policy(Set) document, sorted from latest to oldest, from a directory where each file is named '${version}suffix' representing a specific XACML Policy(Set) Version (${version})
	 * of this document
	 * 
	 * @param versionsDirectory
	 *            directory containing the Policy(Set) version files
	 * @param filenameSuffixMatchingFilter
	 *            file filter that accepts only policy filenames with a specific suffix (e.g. '.xml'); if null, no filtering
	 * @return versions sorted from latest to oldest
	 * @throws IOException
	 *             error Error listing files in {@code versionsDirectory}
	 * @throws NullPointerException
	 *             if {@code versionsDirectory == null}
	 */
	public static PolicyVersions<Path> getPolicyVersions(final Path versionsDirectory, final SuffixMatchingDirectoryStreamFilter filenameSuffixMatchingFilter) throws IOException
	{
		Preconditions.checkNotNull(versionsDirectory, "Undefined versionsDirectory");
		Preconditions.checkNotNull(versionsDirectory, "Undefined filenameSuffixMatchingFilter");
		final Map<PolicyVersion, Path> versions = HashObjObjMaps.newUpdatableMap();
		try (final DirectoryStream<Path> policyDirStream = Files.newDirectoryStream(versionsDirectory, filenameSuffixMatchingFilter))
		{
			for (final Path policyVersionFilePath : policyDirStream)
			{
				final Path policyVersionFileName = policyVersionFilePath.getFileName();
				if (policyVersionFileName == null)
				{
					throw new IOException("Invalid policy file path: " + policyVersionFilePath);
				}

				final String versionPlusSuffix = policyVersionFileName.toString();
				final String versionId = versionPlusSuffix.substring(0, versionPlusSuffix.length() - filenameSuffixMatchingFilter.pathSuffix.length());
				final PolicyVersion version = new PolicyVersion(versionId);
				versions.put(version, policyVersionFilePath);
			}
		}
		catch (final IOException e)
		{
			throw e;
		}

		return new PolicyVersions<>(versions);
	}

	private FlatFileDAOUtils()
	{
	}

	// public static void main(String[] args)
	// {
	// String input = "mus#321=dis?lmth.xedni/DSX/moc.gnaygnoreh//:ptth";
	// // String input = "mailto:herong_yang@yahoo.com";
	//
	// System.out.println("input: " + input);
	// // NB: instead of google BaseEncoding, use
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
