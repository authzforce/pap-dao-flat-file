/**
 * Copyright (C) 2012-2016 Thales Services SAS.
 *
 * This file is part of AuthZForce CE.
 *
 * AuthZForce CE is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * AuthZForce CE is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with AuthZForce CE. If not, see <http://www.gnu.org/licenses/>.
 */
package org.ow2.authzforce.pap.dao.file;

import java.io.File;
import java.io.FileFilter;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.xml.bind.JAXBException;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.PolicySet;

import org.ow2.authzforce.core.pdp.api.CombiningAlgRegistry;
import org.ow2.authzforce.core.pdp.api.EnvironmentProperties;
import org.ow2.authzforce.core.pdp.api.ExpressionFactory;
import org.ow2.authzforce.core.pdp.api.IPolicyEvaluator;
import org.ow2.authzforce.core.pdp.api.IndeterminateEvaluationException;
import org.ow2.authzforce.core.pdp.api.JaxbXACMLUtils.XACMLParserFactory;
import org.ow2.authzforce.core.pdp.api.PolicyVersion;
import org.ow2.authzforce.core.pdp.api.RefPolicyProviderModule;
import org.ow2.authzforce.core.pdp.api.StatusHelper;
import org.ow2.authzforce.core.pdp.api.VersionPatterns;
import org.ow2.authzforce.core.pdp.api.XMLUtils.NamespaceFilteringParser;
import org.ow2.authzforce.core.pdp.impl.policy.PolicyEvaluator;
import org.ow2.authzforce.core.pdp.impl.policy.PolicySetEvaluator;
import org.ow2.authzforce.core.pdp.impl.policy.PolicyVersions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.ResourceUtils;

/**
 * Static Ref Policy Provider for the File-based PAP DAO. This provider expects to find a XACML PolicySet file at
 * PARENT_DIRECTORY/base64url(${PolicySetId})/${Version}SUFFIX. PolicySetId and Version are the respective XACML attributes of the PolicySet. PARENT_DIRECTORY
 * is the parent directory where all policies are located, one directory per each policy (one sub-file per policy version), as defined by the 'policyLocation'
 * attribute.
 * <p>
 * 'base64url' function refers to Base64url encoding specified by RFC 4648, without padding.
 */
public final class FileBasedDAORefPolicyProviderModule implements RefPolicyProviderModule
{
	private static final IllegalArgumentException NULL_POLICY_LOCATION_PATTERN_ARGUMENT_EXCEPTION = new IllegalArgumentException(
			"policyLocationPattern argument undefined");

	private static final IllegalArgumentException NULL_XML_CONF_ARGUMENT_EXCEPTION = new IllegalArgumentException("XML/JAXB configuration argument undefined");

	/**
	 * Validate provider config and returns policy parent directory and policy (version-specific) filename suffix
	 * 
	 * @param policyLocationPattern
	 *            policy location pattern, expected to be PARENT_DIRECTORY/*SUFFIX, where PARENT_DIRECTORY is a valid directory path where the policies should
	 *            be located.
	 * @return entry where the key is the parent directory to all policies, and the value is the policy filename suffix for each policy version
	 * @throws IllegalArgumentException
	 *             if the policyLocationPattern is invalid
	 */
	public static Entry<File, String> validateConf(String policyLocationPattern) throws IllegalArgumentException
	{
		if (policyLocationPattern == null)
		{
			throw NULL_POLICY_LOCATION_PATTERN_ARGUMENT_EXCEPTION;
		}

		final int index = policyLocationPattern.indexOf("/*");
		if (index == -1)
		{
			throw new IllegalArgumentException("Invalid policyLocationPattern in refPolicyProvider configuration: " + policyLocationPattern
					+ ": '/*' not found");
		}

		final String prefix = policyLocationPattern.substring(0, index);
		final File policyParentDirectory;
		try
		{
			policyParentDirectory = ResourceUtils.getFile(prefix);
		} catch (FileNotFoundException e)
		{
			throw new IllegalArgumentException("Invalid policy directory path in refPolicyProvider/policyLocationPattern (prefix before '/*'): "
					+ policyLocationPattern, e);
		}

		final String suffix = policyLocationPattern.substring(index + 2);
		return new SimpleImmutableEntry<>(policyParentDirectory, suffix);
	}

	private static final class SuffixMatchingFileFilter implements FileFilter
	{
		private final String suffix;

		private SuffixMatchingFileFilter(String suffix)
		{
			this.suffix = suffix;
		}

		@Override
		public boolean accept(File file)
		{
			return file.isFile() && file.canRead() && file.getName().endsWith(suffix);
		}
	}

	/**
	 * Module factory
	 *
	 */
	public static class Factory extends RefPolicyProviderModule.Factory<StaticFileBasedDAORefPolicyProvider>
	{
		private static final IllegalArgumentException ILLEGAL_COMBINING_ALG_REGISTRY_ARGUMENT_EXCEPTION = new IllegalArgumentException(
				"Undefined CombiningAlgorithm registry");
		private static final IllegalArgumentException ILLEGAL_EXPRESSION_FACTORY_ARGUMENT_EXCEPTION = new IllegalArgumentException(
				"Undefined Expression factory");
		private static final IllegalArgumentException ILLEGAL_XACML_PARSER_FACTORY_ARGUMENT_EXCEPTION = new IllegalArgumentException(
				"Undefined XACML parser factory");

		@Override
		public RefPolicyProviderModule getInstance(StaticFileBasedDAORefPolicyProvider conf, XACMLParserFactory xacmlParserFactory, int maxPolicySetRefDepth,
				ExpressionFactory expressionFactory, CombiningAlgRegistry combiningAlgRegistry, EnvironmentProperties environmentProperties)
				throws IllegalArgumentException
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
			final Entry<File, String> result = validateConf(policyLocationPattern);
			return new FileBasedDAORefPolicyProviderModule(result.getKey(), result.getValue(), xacmlParserFactory, expressionFactory, combiningAlgRegistry,
					maxPolicySetRefDepth);
		}

		@Override
		public Class<StaticFileBasedDAORefPolicyProvider> getJaxbClass()
		{
			return StaticFileBasedDAORefPolicyProvider.class;
		}

	}

	private static final IllegalArgumentException UNSUPPORTED_POLICY_REFERENCE_EXCEPTION = new IllegalArgumentException("PolicyIdReferences not supported");
	private static final Logger LOGGER = LoggerFactory.getLogger(FileBasedDAORefPolicyProviderModule.class);

	private final File policyParentDirectory;
	private final FileFilter filenameFilter;
	private final XACMLParserFactory xacmlParserFactory;
	private final ExpressionFactory expressionFactory;
	private final CombiningAlgRegistry combiningAlgRegistry;
	private final int maxPolicyRefDepth;

	private class PolicyProxy
	{
		private final File policyFile;
		private PolicySetEvaluator policyEvaluator = null;

		private PolicyProxy(File policyFile)
		{
			assert policyFile != null;
			this.policyFile = policyFile;
		}

		private PolicySetEvaluator getEvaluator(Deque<String> policySetRefChain) throws IndeterminateEvaluationException
		{
			assert policySetRefChain != null;

			if (policyEvaluator == null)
			{
				// PolicyEvaluator not instantiated yet
				final URL policyURL;
				try
				{
					policyURL = policyFile.toURI().toURL();
				} catch (MalformedURLException e)
				{
					throw new IndeterminateEvaluationException("Failed to get Policy(Set) XML document from policy file: " + policyFile,
							StatusHelper.STATUS_PROCESSING_ERROR, e);
				}

				final NamespaceFilteringParser xacmlParser;
				final Object jaxbPolicyOrPolicySetObj;
				try
				{
					xacmlParser = xacmlParserFactory.getInstance();
					jaxbPolicyOrPolicySetObj = xacmlParser.parse(policyURL);
				} catch (JAXBException e)
				{
					throw new IndeterminateEvaluationException("Failed to unmarshall Policy(Set) XML document from policy location: " + policyURL,
							StatusHelper.STATUS_PROCESSING_ERROR, e);
				}

				if (!(jaxbPolicyOrPolicySetObj instanceof PolicySet))
				{
					throw new IndeterminateEvaluationException("Unexpected/unsupported element found as root of the XML document at policy location '"
							+ policyURL + "': " + jaxbPolicyOrPolicySetObj.getClass().getSimpleName(), StatusHelper.STATUS_PROCESSING_ERROR);

				}

				final PolicySet jaxbPolicySet = (PolicySet) jaxbPolicyOrPolicySetObj;
				try
				{
					policyEvaluator = PolicySetEvaluator.getInstance(jaxbPolicySet, null, xacmlParser.getNamespacePrefixUriMap(), expressionFactory,
							combiningAlgRegistry, FileBasedDAORefPolicyProviderModule.this, policySetRefChain);
				} catch (IllegalArgumentException e)
				{
					throw new IndeterminateEvaluationException("Invalid PolicySet in file: " + policyFile, StatusHelper.STATUS_PROCESSING_ERROR, e);
				}
			}

			return policyEvaluator;
		}
	}

	private final Map<String, PolicyVersions<PolicyProxy>> policySetMap = new HashMap<>();
	private final int policyFilenameSuffixLength;

	private FileBasedDAORefPolicyProviderModule(File policyParentDirectory, final String suffix, XACMLParserFactory xacmlParserFactory,
			ExpressionFactory expressionFactory, CombiningAlgRegistry combiningAlgRegistry, int maxPolicySetRefDepth)
	{
		assert policyParentDirectory != null;
		assert xacmlParserFactory != null;
		assert expressionFactory != null;
		assert combiningAlgRegistry != null;

		FileBasedDAOUtils.checkFile("RefPolicyProvider's policy directory", policyParentDirectory, true, false);
		this.policyParentDirectory = policyParentDirectory;
		this.filenameFilter = new SuffixMatchingFileFilter(suffix);
		this.policyFilenameSuffixLength = suffix.length();
		this.xacmlParserFactory = xacmlParserFactory;
		this.expressionFactory = expressionFactory;
		this.combiningAlgRegistry = combiningAlgRegistry;
		this.maxPolicyRefDepth = maxPolicySetRefDepth;

	}

	@Override
	public boolean isStatic()
	{
		return true;
	}

	@Override
	public <POLICY_T extends IPolicyEvaluator> POLICY_T get(Class<POLICY_T> policyType, String id, VersionPatterns versionPatterns,
			Deque<String> ancestorPolicyRefChain) throws IndeterminateEvaluationException, IllegalArgumentException
	{
		final Entry<PolicyVersion, PolicyProxy> policyEntry;
		if (policyType == PolicyEvaluator.class)
		{
			throw UNSUPPORTED_POLICY_REFERENCE_EXCEPTION;
		}

		final Deque<String> newPolicyRefChain = Utils.appendAndCheckPolicyRefChain(ancestorPolicyRefChain, Collections.singletonList(id), maxPolicyRefDepth);

		// Request for PolicySetEvaluator (from PolicySetIdReference)
		final PolicyVersions<PolicyProxy> oldPolicyVersions = policySetMap.get(id);
		final PolicyVersions<PolicyProxy> newPolicyVersions;
		if (oldPolicyVersions == null)
		{
			// policySetMap is lazily populated, so it may mean that the policy directory is there on the filesystem, but not yet added to the map
			// policy directory name is base64url(policyid)
			final String policyDirname = FileBasedDAOUtils.base64UrlEncode(id);
			final File policyFile = new File(policyParentDirectory, policyDirname);
			final File[] files = policyFile.listFiles(filenameFilter);
			if (files == null)
			{
				LOGGER.warn(
						"No valid policy directory found for policy '{}' under directory '{}' or I/O error occured trying to access files (policy versions) in the directory",
						id, policyParentDirectory);
				return null;
			}

			newPolicyVersions = new PolicyVersions<>();
			for (final File file : files)
			{
				newPolicyVersions.put(new PolicyVersion(getVersion(file)), new PolicyProxy(file));
			}

			policySetMap.put(id, newPolicyVersions);

		} else
		{
			newPolicyVersions = oldPolicyVersions;
		}

		policyEntry = newPolicyVersions.getLatest(versionPatterns);
		if (policyEntry == null)
		{
			return null;
		}

		final int refChainLenBefore = newPolicyRefChain.size();
		final PolicySetEvaluator policyEvaluator = policyEntry.getValue().getEvaluator(newPolicyRefChain);
		final List<String> resultPolicyLongestRefChain = policyEvaluator.getLongestPolicyReferenceChain();
		/*
		 * If there is a longest ref chain in result policy, but newPolicyRefChain was not updated with it (length unchanged, i.e. same as before the get(...)),
		 * it means the policy was already parsed before this retrieval (longest ref chain already computed). Therefore, we need to take into account the
		 * longest policy ref chain already computed in the result policy with the current policy ref chain up to this result policy, i.e. newPolicyRefChain;
		 * and check the total chain length.
		 */
		if (resultPolicyLongestRefChain != null && !resultPolicyLongestRefChain.isEmpty() && newPolicyRefChain.size() == refChainLenBefore)
		{
			// newPolicyRefChain was not updated, so we assumed the result policy was already parsed, and longest ref chain already computed
			// To get the new longest ref chain, we need to combine the two
			Utils.appendAndCheckPolicyRefChain(newPolicyRefChain, resultPolicyLongestRefChain, maxPolicyRefDepth);
		}

		return policyType.cast(policyEvaluator);
	}

	private String getVersion(File file)
	{
		assert file != null;

		final String filename = file.getName();
		return filename.substring(0, filename.length() - policyFilenameSuffixLength);

	}

	@Override
	public void close() throws IOException
	{
		policySetMap.clear();

	}

}
