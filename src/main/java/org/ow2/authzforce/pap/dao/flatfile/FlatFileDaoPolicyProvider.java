/*
 * Copyright (C) 2012-2022 THALES.
 *
 * This file is part of AuthzForce CE.
 *
 * AuthzForce CE is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * AuthzForce CE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with AuthzForce CE.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.ow2.authzforce.pap.dao.flatfile;

import org.ow2.authzforce.core.pap.api.dao.AuthzPolicy;
import org.ow2.authzforce.core.pdp.api.EnvironmentProperties;
import org.ow2.authzforce.core.pdp.api.HashCollections;
import org.ow2.authzforce.core.pdp.api.IndeterminateEvaluationException;
import org.ow2.authzforce.core.pdp.api.XmlUtils.XmlnsFilteringParserFactory;
import org.ow2.authzforce.core.pdp.api.combining.CombiningAlgRegistry;
import org.ow2.authzforce.core.pdp.api.expression.ExpressionFactory;
import org.ow2.authzforce.core.pdp.api.policy.*;
import org.ow2.authzforce.core.pdp.impl.policy.PolicyEvaluators;
import org.ow2.authzforce.core.pdp.impl.policy.PolicyMap;
import org.ow2.authzforce.pap.dao.flatfile.FlatFileDAOUtils.SuffixMatchingDirectoryStreamFilter;
import org.ow2.authzforce.pap.dao.flatfile.xmlns.StaticFlatFileDaoPolicyProviderDescriptor;
import org.ow2.authzforce.xacml.identifiers.XacmlStatusCode;
import org.springframework.util.ResourceUtils;

import javax.xml.bind.JAXBException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;

/**
 * Static Policy Provider for the File-based PAP DAO. This provider expects to find a XACML PolicySet file at PARENT_DIRECTORY/base64url(${PolicySetId})/${Version}SUFFIX. PolicySetId and Version are
 * the respective XACML attributes of the PolicySet. PARENT_DIRECTORY is the parent directory where all policies are located, one directory per each policy (one sub-file per policy version), as
 * defined by the 'policyLocation' attribute.
 * <p>
 * 'base64url' function refers to Base64url encoding specified by RFC 4648, without padding.
 */
public final class FlatFileDaoPolicyProvider extends BaseStaticPolicyProvider
{
	private static final IllegalArgumentException NULL_POLICY_LOCATION_PATTERN_ARGUMENT_EXCEPTION = new IllegalArgumentException("policyLocationPattern argument undefined");

	private static final IllegalArgumentException NULL_XML_CONF_ARGUMENT_EXCEPTION = new IllegalArgumentException("XML/JAXB configuration argument undefined");

	/**
	 * Validate provider config and returns policy parent directory and policy (version-specific) filename suffix
	 * 
	 * @param policyLocationPattern
	 *            policy location pattern, expected to be PARENT_DIRECTORY/*SUFFIX, where PARENT_DIRECTORY is a valid directory path where the policies should be located.
	 * @return entry where the key is the parent directory to all policies, and the value is the policy filename suffix for each policy version
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
			throw new IllegalArgumentException("Invalid policyLocationPattern in policyProvider configuration: " + policyLocationPattern + ": '/*' not found");
		}

		final String prefix = policyLocationPattern.substring(0, index);
		final Path policyParentDirectory;
		try
		{
			policyParentDirectory = ResourceUtils.getFile(prefix).toPath();
		}
		catch (final FileNotFoundException e)
		{
			throw new IllegalArgumentException("Invalid policy directory path in policyProvider/policyLocationPattern (prefix before '/*'): " + policyLocationPattern, e);
		}

		final String suffix = policyLocationPattern.substring(index + 2);
		return new SimpleImmutableEntry<>(policyParentDirectory, suffix);
	}

	private final ExpressionFactory expressionFactory;
	private final CombiningAlgRegistry combiningAlgRegistry;
	// policyId -> cache(PolicySets by policy version)
	private final PolicyMap<PolicyEvaluatorSupplier> policyCache;

	private FlatFileDaoPolicyProvider(final Path policyParentDirectory, final String suffix, final XmlnsFilteringParserFactory xacmlParserFactory, final ExpressionFactory expressionFactory,
	        final CombiningAlgRegistry combiningAlgRegistry, final int maxPolicySetRefDepth) throws IllegalArgumentException
	{
		super(maxPolicySetRefDepth);
		assert policyParentDirectory != null;
		assert xacmlParserFactory != null;
		assert expressionFactory != null;
		assert combiningAlgRegistry != null;

		FlatFileDAOUtils.checkFile("PolicyProvider's policy directory", policyParentDirectory, true, false);
		final Map<String, Map<PolicyVersion, PolicyEvaluatorSupplier>> updatablePolicyMap = HashCollections.newUpdatableMap();
		// filter matching specifc file suffix for policy files
		final Filter<? super Path> policyFilenameSuffixMatchingDirStreamFilter = new SuffixMatchingDirectoryStreamFilter(suffix);
		try (DirectoryStream<Path> policyParentDirStream = Files.newDirectoryStream(policyParentDirectory, FlatFileDAOUtils.SUB_DIRECTORY_STREAM_FILTER))
		{
			// Browse directories of policies, one for each policy ID
			for (final Path policyVersionsDir : policyParentDirStream)
			{
				/*
				 * FindBugs considers there is a potential NullPointerException here since getFileName() may be null
				 */
				final Path lastPathSegment = policyVersionsDir.getFileName();
				if (lastPathSegment == null)
				{
					throw new IllegalArgumentException("Invalid policy directory: no filename (root of filesystem?): " + policyVersionsDir);
				}

				final String policyDirName = lastPathSegment.toString();
				final String policyId;
				try
				{
					policyId = FlatFileDAOUtils.base64UrlDecode(policyDirName);
				}
				catch (final IllegalArgumentException e)
				{
					throw new IllegalArgumentException("Invalid policy directory: bad filename (not Base64URL-encoded): " + policyDirName, e);
				}

				final Map<PolicyVersion, PolicyEvaluatorSupplier> policySetSuppliersByVersion = HashCollections.newUpdatableMap();
				// Browse policy versions, one policy file for each version of
				// the current policy
				try (DirectoryStream<Path> policyVersionsDirStream = Files.newDirectoryStream(policyVersionsDir, policyFilenameSuffixMatchingDirStreamFilter))
				{
					for (final Path policyVersionFile : policyVersionsDirStream)
					{
						/*
						 * The PolicyEvaluator supplier (from file) allows to instantiate the Evaluator only if needed, because the instantiation of a PolicyEvaluator from a file is expensive.
						 */
						policySetSuppliersByVersion.put(new PolicyVersion(FlatFileDAOUtils.getPrefix(policyVersionFile, suffix.length())), new PolicyEvaluatorSupplier(policyVersionFile));
					}
				}
				catch (final IOException e)
				{
					throw new IllegalArgumentException("Error listing files of each version of policy '" + policyId + "' in directory: " + policyParentDirectory, e);
				}

				updatablePolicyMap.put(policyId, policySetSuppliersByVersion);
			}
		}
		catch (final IOException e)
		{
			throw new IllegalArgumentException("Error listing files in policies parent directory '" + policyParentDirectory, e);
		}

		this.policyCache = new PolicyMap<>(updatablePolicyMap);
		this.expressionFactory = expressionFactory;
		this.combiningAlgRegistry = combiningAlgRegistry;
	}

	@Override
	public StaticTopLevelPolicyElementEvaluator getPolicy(final String id, final Optional<PolicyVersionPatterns> versionPatterns)
	{
		/*
		 * PolicyIdReferences not supported
		 */
		return null;
	}

	@Override
	public StaticTopLevelPolicyElementEvaluator getPolicySet(final String id, final Optional<PolicyVersionPatterns> versionPatterns, final Deque<String> policySetRefChain)
	        throws IndeterminateEvaluationException
	{
		// Request for PolicySetEvaluator (from PolicySetIdReference)
		final Entry<PolicyVersion, PolicyEvaluatorSupplier> policyEntry = policyCache.get(id, versionPatterns);
		if (policyEntry == null)
		{
			return null;
		}

		final StaticTopLevelPolicyElementEvaluator policyEvaluator;
		try
		{
			policyEvaluator = policyEntry.getValue().get(this, policySetRefChain);
		}
		catch (final IndeterminateEvaluationException e)
		{
			// throw back an high-level exception message for easier
			// troubleshooting (no file path)
			final PolicyVersion version = policyEntry.getKey();
			throw new IndeterminateEvaluationException("Matched PolicySet '" + id + "' (version " + version + ") is invalid or its content is unavailable", XacmlStatusCode.PROCESSING_ERROR.value(),
			        e);
		}

		/*
		 * Validate the merged policyset ref chain if policySetRefChain != null
		 */
		if (policySetRefChain != null && !policySetRefChain.isEmpty())
		{
			final Optional<PolicyRefsMetadata> policyRefsMeta = policyEvaluator.getPolicyRefsMetadata();
			/*
			 * If there is a longest ref chain in result policy, this means it is a PolicySet that may have PolicySetIdReferences, so we need to take into account the longest policy ref chain within
			 * it, i.e. add this longest chain to policyRefChainFromRootToRequestedPolicyIncluded (the policy ref chain up to this result policy), to get and check the total chain length.
			 */
			if (policyRefsMeta.isPresent())
			{
				final List<String> resultPolicyLongestRefChain = policyRefsMeta.get().getLongestPolicyRefChain();
				if (!resultPolicyLongestRefChain.isEmpty())
				{
					// newPolicyRefChain was not updated, so we assumed the result
					// policy was already parsed, and longest ref chain already computed
					// To get the new longest ref chain, we need to combine the two
					joinPolicyRefChains(policySetRefChain, resultPolicyLongestRefChain);
				}
			}
		}

		return policyEvaluator;
	}

	@Override
	public void close()
	{
		/*
		 * The policyCache has been made immutable so we cannot call the clear() method
		 */
		// this.policyCache.clear();
	}

	/*
	 * Lazy initializing policy evaluator, i.e. only when the policy is actually requested; because this job is expensive.
	 */
	private static final class PolicyEvaluatorSupplier
	{
		private final Path policyFilepath;
		private transient StaticTopLevelPolicyElementEvaluator policyEvaluator = null;

		private PolicyEvaluatorSupplier(final Path policyFilepath)
		{
			assert policyFilepath != null && Files.isRegularFile(policyFilepath, LinkOption.NOFOLLOW_LINKS) && Files.isReadable(policyFilepath);
			this.policyFilepath = policyFilepath;
		}

		private StaticTopLevelPolicyElementEvaluator get(final FlatFileDaoPolicyProvider policyProviderModule, final Deque<String> policySetRefChain) throws IndeterminateEvaluationException
		{
			/*
			 * Prevent simulatenous attemps to initialize the policy evaluator. Must be done by a single thread once and for all
			 */
			synchronized (policyFilepath)
			{
				if (policyEvaluator == null)
				{
					if (!Files.isRegularFile(policyFilepath, LinkOption.NOFOLLOW_LINKS))
					{
						throw new IndeterminateEvaluationException("Unable to find PolicySet file: " + policyFilepath, XacmlStatusCode.PROCESSING_ERROR.value());
					}

					final AuthzPolicy authzPolicy;
					try
					{
						authzPolicy = FlatFileDAOUtils.loadPolicy(policyFilepath);
					}
					catch (final IllegalArgumentException e)
					{
						throw new IndeterminateEvaluationException("Invalid PolicySet in file: " + policyFilepath, XacmlStatusCode.PROCESSING_ERROR.value(), e);
					}
					catch (final JAXBException e1)
					{
						throw new IndeterminateEvaluationException("Error loading PolicySet from file: " + policyFilepath, XacmlStatusCode.PROCESSING_ERROR.value(), e1);
					}
					try
					{
						policyEvaluator = PolicyEvaluators.getInstanceStatic(authzPolicy.toXacml(), policyProviderModule.expressionFactory,  policyProviderModule.combiningAlgRegistry, policyProviderModule,
								policySetRefChain, Optional.empty(), authzPolicy.getXPathNamespaceContexts());
					}
					catch (final IllegalArgumentException e)
					{
						throw new IndeterminateEvaluationException("Invalid PolicySet in file: " + policyFilepath, XacmlStatusCode.PROCESSING_ERROR.value(), e);
					}
				}
			}

			return policyEvaluator;
		}
	}

	/**
	 * Module factory
	 *
	 */
	public static final class Factory extends CloseablePolicyProvider.Factory<StaticFlatFileDaoPolicyProviderDescriptor>
	{
		private static final IllegalArgumentException ILLEGAL_COMBINING_ALG_REGISTRY_ARGUMENT_EXCEPTION = new IllegalArgumentException("Undefined CombiningAlgorithm registry");
		private static final IllegalArgumentException ILLEGAL_EXPRESSION_FACTORY_ARGUMENT_EXCEPTION = new IllegalArgumentException("Undefined Expression factory");
		private static final IllegalArgumentException ILLEGAL_XACML_PARSER_FACTORY_ARGUMENT_EXCEPTION = new IllegalArgumentException("Undefined XACML parser factory");

		@Override
		public CloseablePolicyProvider<?> getInstance(final StaticFlatFileDaoPolicyProviderDescriptor conf, final XmlnsFilteringParserFactory xacmlParserFactory, final int maxPolicySetRefDepth,
		        final ExpressionFactory expressionFactory, final CombiningAlgRegistry combiningAlgRegistry, final EnvironmentProperties environmentProperties,
		        final Optional<PolicyProvider<?>> otherHelpingPolicyProvider) throws IllegalArgumentException
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

			final String policyLocationPattern = environmentProperties.replacePlaceholders(conf.getPolicyLocationPattern());
			final Entry<Path, String> result = validateConf(policyLocationPattern);
			return new FlatFileDaoPolicyProvider(result.getKey(), result.getValue(), xacmlParserFactory, expressionFactory, combiningAlgRegistry, maxPolicySetRefDepth);
		}

		@Override
		public Class<StaticFlatFileDaoPolicyProviderDescriptor> getJaxbClass()
		{
			return StaticFlatFileDaoPolicyProviderDescriptor.class;
		}

	}

}
