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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.xml.bind.JAXBException;

import org.ow2.authzforce.core.pdp.api.EnvironmentProperties;
import org.ow2.authzforce.core.pdp.api.EvaluationContext;
import org.ow2.authzforce.core.pdp.api.IndeterminateEvaluationException;
import org.ow2.authzforce.core.pdp.api.JaxbXACMLUtils.XACMLParserFactory;
import org.ow2.authzforce.core.pdp.api.StatusHelper;
import org.ow2.authzforce.core.pdp.api.XMLUtils.NamespaceFilteringParser;
import org.ow2.authzforce.core.pdp.api.combining.CombiningAlgRegistry;
import org.ow2.authzforce.core.pdp.api.expression.ExpressionFactory;
import org.ow2.authzforce.core.pdp.api.policy.PolicyVersion;
import org.ow2.authzforce.core.pdp.api.policy.RefPolicyProviderModule;
import org.ow2.authzforce.core.pdp.api.policy.StaticRefPolicyProviderModule;
import org.ow2.authzforce.core.pdp.api.policy.StaticTopLevelPolicyElementEvaluator;
import org.ow2.authzforce.core.pdp.api.policy.TopLevelPolicyElementEvaluator;
import org.ow2.authzforce.core.pdp.api.policy.TopLevelPolicyElementType;
import org.ow2.authzforce.core.pdp.api.policy.VersionPatterns;
import org.ow2.authzforce.core.pdp.impl.policy.PolicyEvaluators;
import org.ow2.authzforce.core.pdp.impl.policy.PolicyVersions;
import org.ow2.authzforce.pap.dao.flatfile.FlatFileDAOUtils.SuffixMatchingDirectoryStreamFilter;
import org.ow2.authzforce.pap.dao.flatfile.xmlns.StaticFlatFileDAORefPolicyProvider;
import org.springframework.util.ResourceUtils;

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.koloboke.collect.map.hash.HashObjObjMaps;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.PolicySet;

/**
 * Static Ref Policy Provider for the File-based PAP DAO. This provider expects
 * to find a XACML PolicySet file at
 * PARENT_DIRECTORY/base64url(${PolicySetId})/${Version}SUFFIX. PolicySetId and
 * Version are the respective XACML attributes of the PolicySet.
 * PARENT_DIRECTORY is the parent directory where all policies are located, one
 * directory per each policy (one sub-file per policy version), as defined by
 * the 'policyLocation' attribute.
 * <p>
 * 'base64url' function refers to Base64url encoding specified by RFC 4648,
 * without padding.
 */
public final class FlatFileDAORefPolicyProviderModule implements StaticRefPolicyProviderModule
{
	private static final IllegalArgumentException NULL_POLICY_LOCATION_PATTERN_ARGUMENT_EXCEPTION = new IllegalArgumentException(
			"policyLocationPattern argument undefined");

	private static final IllegalArgumentException NULL_XML_CONF_ARGUMENT_EXCEPTION = new IllegalArgumentException(
			"XML/JAXB configuration argument undefined");

	private static final IllegalArgumentException UNSUPPORTED_POLICY_REFERENCE_EXCEPTION = new IllegalArgumentException(
			"PolicyIdReferences not supported");

	/**
	 * Validate provider config and returns policy parent directory and policy
	 * (version-specific) filename suffix
	 * 
	 * @param policyLocationPattern
	 *            policy location pattern, expected to be
	 *            PARENT_DIRECTORY/*SUFFIX, where PARENT_DIRECTORY is a valid
	 *            directory path where the policies should be located.
	 * @return entry where the key is the parent directory to all policies, and
	 *         the value is the policy filename suffix for each policy version
	 * @throws IllegalArgumentException
	 *             if the policyLocationPattern is invalid
	 */
	public static Entry<Path, String> validateConf(final String policyLocationPattern) throws IllegalArgumentException
	{
		if (policyLocationPattern == null)
		{
			throw NULL_POLICY_LOCATION_PATTERN_ARGUMENT_EXCEPTION;
		}

		final int index = policyLocationPattern.indexOf("/*");
		if (index == -1)
		{
			throw new IllegalArgumentException("Invalid policyLocationPattern in refPolicyProvider configuration: "
					+ policyLocationPattern + ": '/*' not found");
		}

		final String prefix = policyLocationPattern.substring(0, index);
		final Path policyParentDirectory;
		try
		{
			policyParentDirectory = ResourceUtils.getFile(prefix).toPath();
		}
		catch (final FileNotFoundException e)
		{
			throw new IllegalArgumentException(
					"Invalid policy directory path in refPolicyProvider/policyLocationPattern (prefix before '/*'): "
							+ policyLocationPattern,
					e);
		}

		final String suffix = policyLocationPattern.substring(index + 2);
		return new SimpleImmutableEntry<>(policyParentDirectory, suffix);
	}

	/**
	 * Module factory
	 *
	 */
	public static class Factory extends RefPolicyProviderModule.Factory<StaticFlatFileDAORefPolicyProvider>
	{
		private static final IllegalArgumentException ILLEGAL_COMBINING_ALG_REGISTRY_ARGUMENT_EXCEPTION = new IllegalArgumentException(
				"Undefined CombiningAlgorithm registry");
		private static final IllegalArgumentException ILLEGAL_EXPRESSION_FACTORY_ARGUMENT_EXCEPTION = new IllegalArgumentException(
				"Undefined Expression factory");
		private static final IllegalArgumentException ILLEGAL_XACML_PARSER_FACTORY_ARGUMENT_EXCEPTION = new IllegalArgumentException(
				"Undefined XACML parser factory");

		@Override
		public RefPolicyProviderModule getInstance(final StaticFlatFileDAORefPolicyProvider conf,
				final XACMLParserFactory xacmlParserFactory, final int maxPolicySetRefDepth,
				final ExpressionFactory expressionFactory, final CombiningAlgRegistry combiningAlgRegistry,
				final EnvironmentProperties environmentProperties) throws IllegalArgumentException
		{
			if (conf == null)
			{
				throw NULL_XML_CONF_ARGUMENT_EXCEPTION;
			}

			if (xacmlParserFactory == null)
			{
				throw ILLEGAL_XACML_PARSER_FACTORY_ARGUMENT_EXCEPTION;
			}

			if (expressionFactory == null)
			{
				throw ILLEGAL_EXPRESSION_FACTORY_ARGUMENT_EXCEPTION;
			}

			if (combiningAlgRegistry == null)
			{
				throw ILLEGAL_COMBINING_ALG_REGISTRY_ARGUMENT_EXCEPTION;
			}

			final String policyLocationPattern = environmentProperties
					.replacePlaceholders(conf.getPolicyLocationPattern());
			final Entry<Path, String> result = validateConf(policyLocationPattern);
			return new FlatFileDAORefPolicyProviderModule(result.getKey(), result.getValue(), xacmlParserFactory,
					expressionFactory, combiningAlgRegistry, maxPolicySetRefDepth);
		}

		@Override
		public Class<StaticFlatFileDAORefPolicyProvider> getJaxbClass()
		{
			return StaticFlatFileDAORefPolicyProvider.class;
		}

	}

	private static class PolicySupplier implements Supplier<PolicySet>
	{
		private final Path policyVersionFile;

		private transient PolicySet jaxbPolicySet = null;
		private transient volatile StaticTopLevelPolicyElementEvaluator policyEvaluator = null;

		private PolicySupplier(final Path policyVersionFile)
		{
			assert policyVersionFile != null;
			this.policyVersionFile = policyVersionFile;
		}

		private PolicySet getPolicySet()
		{
			final URL policyURL;
			try
			{
				policyURL = policyVersionFile.toUri().toURL();
			}
			catch (final MalformedURLException e)
			{
				throw new IndeterminateEvaluationException(
						"Failed to get Policy(Set) XML document from policy file: " + policyVersionFile,
						StatusHelper.STATUS_PROCESSING_ERROR, e);
			}

			final NamespaceFilteringParser xacmlParser;
			final Object jaxbPolicyOrPolicySetObj;
			try
			{
				xacmlParser = xacmlParserFactory.getInstance();
				jaxbPolicyOrPolicySetObj = xacmlParser.parse(policyURL);
			}
			catch (final JAXBException e)
			{
				throw new IndeterminateEvaluationException(
						"Failed to unmarshall Policy(Set) XML document from policy location: " + policyURL,
						StatusHelper.STATUS_PROCESSING_ERROR, e);
			}

			if (!(jaxbPolicyOrPolicySetObj instanceof PolicySet))
			{
				throw new IndeterminateEvaluationException(
						"Unexpected/unsupported element found as root of the XML document at policy location '"
								+ policyURL + "': " + jaxbPolicyOrPolicySetObj.getClass().getSimpleName(),
						StatusHelper.STATUS_PROCESSING_ERROR);

			}
		}

		private StaticTopLevelPolicyElementEvaluator getEvaluator(final Deque<String> policySetRefChain)
				throws IndeterminateEvaluationException
		{
			assert policySetRefChain != null;

			if (policyEvaluator == null)
			{
				// PolicyEvaluator not instantiated yet

				jaxbPolicySet = (PolicySet) jaxbPolicyOrPolicySetObj;
				try
				{
					policyEvaluator = PolicyEvaluators.getInstanceStatic(jaxbPolicySet, null,
							xacmlParser.getNamespacePrefixUriMap(), expressionFactory, combiningAlgRegistry,
							FlatFileDAORefPolicyProviderModule.this, policySetRefChain);
				}
				catch (final IllegalArgumentException e)
				{
					throw new IndeterminateEvaluationException("Invalid PolicySet in file: " + policyVersionFile,
							StatusHelper.STATUS_PROCESSING_ERROR, e);
				}
			}

			return policyEvaluator;
		}

		@Override
		public PolicySet get()
		{
			// TODO Auto-generated method stub
			return null;
		}
	}

	private final DirectoryStream.Filter<? super Path> dirStreamFilter;
	private final XACMLParserFactory xacmlParserFactory;
	private final ExpressionFactory expressionFactory;
	private final CombiningAlgRegistry combiningAlgRegistry;
	private final int maxPolicyRefDepth;
	// policyId -> cache(PolicySets by policy version)
	private final Map<String, PolicyVersions<Supplier<PolicySet>>> policyCache;

	private FlatFileDAORefPolicyProviderModule(final Path policyParentDirectory, final String suffix,
			final XACMLParserFactory xacmlParserFactory, final ExpressionFactory expressionFactory,
			final CombiningAlgRegistry combiningAlgRegistry, final int maxPolicySetRefDepth)
					throws IllegalArgumentException
	{
		assert policyParentDirectory != null;
		assert xacmlParserFactory != null;
		assert expressionFactory != null;
		assert combiningAlgRegistry != null;

		FlatFileDAOUtils.checkFile("RefPolicyProvider's policy directory", policyParentDirectory, true, false);
		/*
		 * We don't parse all policies in directories yet because there may be
		 * plenty of them in different versions and loading a policy from file
		 * is an expensive job, and it is very likely that the root policy will
		 * reference only a few of them, so some of them may never be used.
		 * Therefore, we'll do lazy initialization, i.e. a policy will be
		 * instantiated from file on the fly the first time it is requested, if
		 * and only if it is ever requested, in a way that is thread-safe. Also
		 * the provider's get() should be idempotent, i.e. return the same
		 * policy across multiple calls with same type, id, versionPatterns. In
		 * short, this is a good use case for local in-memory caching, e.g. with
		 * Guava Cache.
		 */
		/*
		 * To size the cache, we count files in the policy parent directory.
		 * There should not be more than that as there should only be at most
		 * one version per policy that is being used at a time
		 * directly/indrectly by the root policy (best practice), else the
		 * policy evaluation may have unexpected / hard-to-troubleshoot
		 * behavior.
		 */
		final Map<String, PolicyVersions<Supplier<PolicySet>>> updatablePolicyMap = HashObjObjMaps.newUpdatableMap();
		// filter matching specifc file suffix for policy files
		final Filter<? super Path> policyFilenameSuffixMatchingDirStreamFilter = new SuffixMatchingDirectoryStreamFilter(
				suffix);
		try (final DirectoryStream<Path> policyParentDirStream = Files.newDirectoryStream(policyParentDirectory,
				FlatFileDAOUtils.SUB_DIRECTORY_STREAM_FILTER))
		{
			// Browse directories of policies, one for each policy ID
			for (final Path policyVersionsDir : policyParentDirStream)
			{
				final String policyDirName = policyVersionsDir.getFileName().toString();
				final String policyId;
				try
				{
					policyId = FlatFileDAOUtils.base64UrlDecode(policyDirName);
				}
				catch (final IllegalArgumentException e)
				{
					throw new IllegalArgumentException(
							"Invalid policy directory: bad filename (not Base64URL-encoded): " + policyDirName, e);
				}

				final Map<PolicyVersion, Supplier<PolicySet>> policySetSuppliersByVersion = HashObjObjMaps
						.newUpdatableMap();
				// Browse policy versions, one policy file for each version of
				// the current policy
				try (final DirectoryStream<Path> policyVersionsDirStream = Files.newDirectoryStream(policyVersionsDir,
						policyFilenameSuffixMatchingDirStreamFilter))
				{
					for (final Path policyVersionFile : policyVersionsDirStream)
					{
						/*
						 * The PolicyEvaluator supplier (from file) allows to
						 * instantiate the Evaluator only if needed, because the
						 * instantiation of a PolicyEvaluator from a file is
						 * expensive.
						 */
						policySetSuppliersByVersion.put(
								new PolicyVersion(FlatFileDAOUtils.getPrefix(policyVersionFile, suffix.length())),
								Suppliers.memoize(new PolicySupplier(policyVersionFile)));
					}
				}
				catch (final IOException e)
				{
					throw new IllegalArgumentException("Error listing files of each version of policy '" + policyId
							+ "' in directory: " + policyParentDirectory, e);
				}

				final PolicyVersions<Supplier<PolicySet>> versions = new PolicyVersions<>(policySetSuppliersByVersion);
				updatablePolicyMap.put(policyId, versions);
			}
		}
		catch (final IOException e)
		{
			throw new IllegalArgumentException(
					"Error listing files in policies parent directory '" + policyParentDirectory, e);
		}

		this.policyCache = HashObjObjMaps.newImmutableMap(updatablePolicyMap);
		this.xacmlParserFactory = xacmlParserFactory;
		this.expressionFactory = expressionFactory;
		this.combiningAlgRegistry = combiningAlgRegistry;
		this.maxPolicyRefDepth = maxPolicySetRefDepth;
	}

	@Override
	public StaticTopLevelPolicyElementEvaluator get(final TopLevelPolicyElementType policyType, final String id,
			final VersionPatterns versionPatterns, final Deque<String> ancestorPolicyRefChain)
					throws IndeterminateEvaluationException
	{
		final Entry<PolicyVersion, FileBasedPolicyInitializer> policyEntry;
		if (policyType == TopLevelPolicyElementType.POLICY)
		{
			throw UNSUPPORTED_POLICY_REFERENCE_EXCEPTION;
		}

		final Deque<String> newPolicyRefChain = Utils.appendAndCheckPolicyRefChain(ancestorPolicyRefChain,
				Collections.singletonList(id), maxPolicyRefDepth);

		// Request for PolicySetEvaluator (from PolicySetIdReference)
		final PolicyVersions<FileBasedPolicyInitializer> oldPolicyVersions = policySetMap.get(id);
		final PolicyVersions<FileBasedPolicyInitializer> newPolicyVersions;
		if (oldPolicyVersions == null)
		{
			newPolicyVersions = new PolicyVersions<>();
			// policySetMap is lazily populated, so it may mean that the policy
			// directory is there on the filesystem, but not yet added to the
			// map
			// policy directory name is base64url(policyid)
			final String policyDirname = FlatFileDAOUtils.base64UrlEncode(id);
			final Path policyFile = policyParentDirectory.resolve(policyDirname);
			try (final DirectoryStream<Path> policyDirStream = Files.newDirectoryStream(policyFile, dirStreamFilter))
			{
				for (final Path file : policyDirStream)
				{
					newPolicyVersions.put(new PolicyVersion(getVersion(file)), new FileBasedPolicyInitializer(file));
				}
			}
			catch (final IOException e)
			{
				throw new IndeterminateEvaluationException(
						"Error resolving policy reference: PolicySet '" + id + "' not available",
						StatusHelper.STATUS_PROCESSING_ERROR, e);
			}

			policySetMap.put(id, newPolicyVersions);
		}
		else
		{
			newPolicyVersions = oldPolicyVersions;
		}

		policyEntry = newPolicyVersions.getLatest(versionPatterns);
		if (policyEntry == null)
		{
			return null;
		}

		final int refChainLenBefore = newPolicyRefChain.size();
		final StaticTopLevelPolicyElementEvaluator policyEvaluator;
		try
		{
			policyEvaluator = policyEntry.getValue().getEvaluator(newPolicyRefChain);
		}
		catch (final IndeterminateEvaluationException e)
		{
			// throw back an high-level exception message for easier
			// troubleshooting (no file path)
			final PolicyVersion version = policyEntry.getKey();
			throw new IndeterminateEvaluationException(
					"Matched PolicySet '" + id + "' (version " + version + ") is invalid or its content is unavailable",
					StatusHelper.STATUS_PROCESSING_ERROR, e);
		}

		final List<String> resultPolicyLongestRefChain = policyEvaluator.getExtraPolicyMetadata()
				.getLongestPolicyRefChain();
		/*
		 * If there is a longest ref chain in result policy, but
		 * newPolicyRefChain was not updated with it (length unchanged, i.e.
		 * same as before the get(...)), it means the policy was already parsed
		 * before this retrieval (longest ref chain already computed).
		 * Therefore, we need to take into account the longest policy ref chain
		 * already computed in the result policy with the current policy ref
		 * chain up to this result policy, i.e. newPolicyRefChain; and check the
		 * total chain length.
		 */
		if (resultPolicyLongestRefChain != null && !resultPolicyLongestRefChain.isEmpty()
				&& newPolicyRefChain.size() == refChainLenBefore)
		{
			// newPolicyRefChain was not updated, so we assumed the result
			// policy was already parsed, and longest ref chain already computed
			// To get the new longest ref chain, we need to combine the two
			Utils.appendAndCheckPolicyRefChain(newPolicyRefChain, resultPolicyLongestRefChain, maxPolicyRefDepth);
		}

		return policyEvaluator;
	}

	@Override
	public TopLevelPolicyElementEvaluator get(final TopLevelPolicyElementType policyType, final String policyId,
			final VersionPatterns policyVersionConstraints, final Deque<String> policySetRefChain,
			final EvaluationContext evaluationCtx) throws IllegalArgumentException, IndeterminateEvaluationException
	{
		return get(policyType, policyId, policyVersionConstraints, policySetRefChain);
	}

	@Override
	public void close() throws IOException
	{
		this.policyCache.clear();

	}

}
