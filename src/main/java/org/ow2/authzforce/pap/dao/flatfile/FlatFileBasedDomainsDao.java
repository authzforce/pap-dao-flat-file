/*
 * Copyright (C) 2012-2024 THALES.
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

import com.fasterxml.uuid.EthernetAddress;
import com.fasterxml.uuid.Generators;
import com.fasterxml.uuid.impl.TimeBasedGenerator;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSortedSet;
import com.google.common.collect.Maps;
import jakarta.xml.bind.*;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.IdReferenceType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.PolicySet;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.Request;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.Response;
import org.apache.cxf.staxutils.StaxUtils;
import org.json.JSONObject;
import org.ow2.authzforce.core.pap.api.dao.*;
import org.ow2.authzforce.core.pdp.api.*;
import org.ow2.authzforce.core.pdp.api.combining.CombiningAlg;
import org.ow2.authzforce.core.pdp.api.func.Function;
import org.ow2.authzforce.core.pdp.api.io.BaseXacmlJaxbResultPostprocessor;
import org.ow2.authzforce.core.pdp.api.io.IndividualXacmlJaxbRequest;
import org.ow2.authzforce.core.pdp.api.io.PdpEngineInoutAdapter;
import org.ow2.authzforce.core.pdp.api.policy.PolicyVersion;
import org.ow2.authzforce.core.pdp.api.policy.PrimaryPolicyMetadata;
import org.ow2.authzforce.core.pdp.api.policy.TopLevelPolicyElementType;
import org.ow2.authzforce.core.pdp.api.value.AttributeValueFactory;
import org.ow2.authzforce.core.pdp.api.value.AttributeValueFactoryRegistry;
import org.ow2.authzforce.core.pdp.impl.*;
import org.ow2.authzforce.core.pdp.impl.io.DecisionRequestPreprocessorSupplier;
import org.ow2.authzforce.core.pdp.impl.io.PdpEngineAdapters;
import org.ow2.authzforce.core.pdp.impl.io.SingleDecisionXacmlJaxbRequestPreprocessor;
import org.ow2.authzforce.core.pdp.impl.policy.PolicyVersions;
import org.ow2.authzforce.core.pdp.io.xacml.json.BaseXacmlJsonResultPostprocessor;
import org.ow2.authzforce.core.pdp.io.xacml.json.IndividualXacmlJsonRequest;
import org.ow2.authzforce.core.pdp.io.xacml.json.SingleDecisionXacmlJsonRequestPreprocessor;
import org.ow2.authzforce.core.xmlns.pdp.InOutProcChain;
import org.ow2.authzforce.core.xmlns.pdp.Pdp;
import org.ow2.authzforce.core.xmlns.pdp.StaticPolicyProvider;
import org.ow2.authzforce.core.xmlns.pdp.TopLevelPolicyElementRef;
import org.ow2.authzforce.pap.dao.flatfile.FlatFileDAOUtils.SuffixMatchingDirectoryStreamFilter;
import org.ow2.authzforce.pap.dao.flatfile.xmlns.DomainProperties;
import org.ow2.authzforce.pap.dao.flatfile.xmlns.StaticFlatFileDaoPolicyProviderDescriptor;
import org.ow2.authzforce.xacml.Xacml3JaxbHelper;
import org.ow2.authzforce.xmlns.pdp.ext.AbstractAttributeProvider;
import org.ow2.authzforce.xmlns.pdp.ext.AbstractPolicyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.util.ResourceUtils;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import java.beans.ConstructorProperties;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.*;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Filesystem-based policy domain repository DAO
 * 
 * @param <VERSION_DAO_CLIENT>
 *            Domain policy version DAO client implementation class
 * 
 * @param <POLICY_DAO_CLIENT>
 *            Domain policy DAO client implementation class
 * 
 * @param <DOMAIN_DAO_CLIENT>
 *            Domain DAO client implementation class
 *
 */
public final class FlatFileBasedDomainsDao<VERSION_DAO_CLIENT extends PolicyVersionDaoClient, POLICY_DAO_CLIENT extends PolicyDaoClient, DOMAIN_DAO_CLIENT extends DomainDaoClient<FlatFileBasedDomainDao<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT>>>
        implements DomainsDao<DOMAIN_DAO_CLIENT>
{
	/**
	 * DOMAIN FILE SYNC THREAD SHUTDOWN TIMEOUT (seconds)
	 */
	public static final int SYNC_SERVICE_SHUTDOWN_TIMEOUT_SEC = 10;

	private static final Logger LOGGER = LoggerFactory.getLogger(FlatFileBasedDomainsDao.class);

	private static final IllegalArgumentException ILLEGAL_CONSTRUCTOR_ARGS_EXCEPTION = new IllegalArgumentException(
	        "One of the following FileBasedDomainsDao constructor arguments is undefined although required: domainsRoot == null || domainTmpl == null || schema == null || pdpModelHandler == null || domainDaoClientFactory == null || policyDaoClientFactory == null");

	private static final IllegalArgumentException NULL_DOMAIN_ID_ARG_EXCEPTION = new IllegalArgumentException("Undefined domain ID arg");

	private static final IllegalArgumentException ILLEGAL_POLICY_NOT_STATIC_EXCEPTION = new IllegalArgumentException(
	        "One of the policy finders in the domain PDP configuration is not static, or one of the policies required by PDP cannot be statically resolved");

	private static final RuntimeException NON_STATIC_POLICY_EXCEPTION = new RuntimeException("Unexpected error: Some policies are not statically resolved (pdp.getStaticApplicablePolicies() == null)");

	private static final IllegalArgumentException NULL_POLICY_ARGUMENT_EXCEPTION = new IllegalArgumentException("Null policySet arg");
	private static final IllegalArgumentException NULL_DOMAIN_PROPERTIES_ARGUMENT_EXCEPTION = new IllegalArgumentException("Null domain properties arg");
	private static final IllegalArgumentException NULL_PRP_PROPERTIES_ARGUMENT_EXCEPTION = new IllegalArgumentException("Null domain PRP properties arg");
	private static final IllegalArgumentException NULL_PDP_PROPERTIES_ARGUMENT_EXCEPTION = new IllegalArgumentException("Null domain PDP properties arg");
	private static final IllegalArgumentException NULL_ROOT_POLICY_REF_ARGUMENT_EXCEPTION = new IllegalArgumentException("Invalid domain PDP properties arg: rootPolicyRef undefined");
	private static final IllegalArgumentException NULL_ATTRIBUTE_PROVIDERS_ARGUMENT_EXCEPTION = new IllegalArgumentException("Null attributeProviders arg");
	private static final UnsupportedOperationException DISABLED_OPERATION_EXCEPTION = new UnsupportedOperationException("Unsupported operation: disabled by configuration");
	private static final RuntimeException PDP_IN_ERROR_STATE_RUNTIME_EXCEPTION = new RuntimeException("PDP in error state. Check the server logs or contact the administrator.");
	private static final UnsupportedOperationException UNSUPPORTED_XACML_JSON_PROFILE_OPERATION_EXCEPTION = new UnsupportedOperationException("Unsupported XACML/JSON (XACML Json Profile) format");

	private static final PolicyVersions<Path> EMPTY_POLICY_VERSIONS = new PolicyVersions<>(Collections.emptyMap());

	/**
	 * Domain properties XSD location
	 */
	public static final String DOMAIN_PROPERTIES_XSD_LOCATION = "classpath:org.ow2.authzforce.pap.dao.flatfile.properties.xsd";

	/**
	 * Name of domain properties file
	 */
	public static final String DOMAIN_PROPERTIES_FILENAME = "properties.xml";

	/**
	 * Name of PDP configuration file
	 */
	public static final String DOMAIN_PDP_CONFIG_FILENAME = "pdp.xml";

	private static final JAXBContext DOMAIN_PROPERTIES_JAXB_CONTEXT;

	static
	{
		try
		{
			DOMAIN_PROPERTIES_JAXB_CONTEXT = JAXBContext.newInstance(DomainProperties.class);
		}
		catch (final JAXBException e)
		{
			throw new RuntimeException("Error creating JAXB context for (un)marshalling domain properties (XML)", e);
		}
	}

	private static final Schema DOMAIN_PROPERTIES_SCHEMA;

	static
	{
		final SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		try
		{
			DOMAIN_PROPERTIES_SCHEMA = schemaFactory.newSchema(ResourceUtils.getURL(DOMAIN_PROPERTIES_XSD_LOCATION));
		}
		catch (final FileNotFoundException e)
		{
			throw new RuntimeException("Domain properties schema not found", e);
		}
		catch (final SAXException e)
		{
			throw new RuntimeException("Invalid domain properties schema file", e);
		}
	}

	private static final IllegalArgumentException INVALID_FEATURE_ID_EXCEPTION = new IllegalArgumentException("Invalid feature ID: undefined");

	private static class ReadableDomainPropertiesImpl implements ReadableDomainProperties
	{

		private final String domainId;
		private final String description;
		private final String externalId;

		private ReadableDomainPropertiesImpl(final String domainId, final String description, final String externalId)
		{
			assert domainId != null;

			this.domainId = domainId;
			this.description = description;
			this.externalId = externalId;
		}

		@Override
		public String getInternalId()
		{
			return domainId;
		}

		@Override
		public String getExternalId()
		{
			return externalId;
		}

		@Override
		public String getDescription()
		{
			return description;
		}

	}

	private static class PrpRwPropertiesImpl implements PrpRwProperties
	{

		private final int maxPolicyCount;
		private final int maxVersionCountPerPolicy;
		private final boolean isVersionRollingEnabled;

		private PrpRwPropertiesImpl(final int maxPolicyCount, final int maxVersionCountPerPolicy, final boolean enableVersionRolling)
		{
			this.maxPolicyCount = maxPolicyCount;
			this.maxVersionCountPerPolicy = maxVersionCountPerPolicy;
			this.isVersionRollingEnabled = enableVersionRolling;
		}

		@Override
		public boolean isVersionRollingEnabled()
		{
			return isVersionRollingEnabled;
		}

		@Override
		public int getMaxVersionCountPerPolicy()
		{
			return maxVersionCountPerPolicy;
		}

		@Override
		public int getMaxPolicyCountPerDomain()
		{
			return maxPolicyCount;
		}

	}

	private static class ReadablePdpPropertiesImpl implements ReadablePdpProperties
	{

		private final List<PdpFeature> features;
		private final IdReferenceType rootPolicyRefExpression;
		private final IdReferenceType applicableRootPolicyRef;
		private final List<IdReferenceType> applicableRefPolicyRefs;
		private final long lastModified;

		private ReadablePdpPropertiesImpl(final List<PdpFeature> features, final TopLevelPolicyElementRef rootPolicyRef, final TopLevelPolicyElementRef applicableRootPolicyRef,
		        final List<TopLevelPolicyElementRef> applicableRefPolicyRefs, final long lastModified)
		{
			assert rootPolicyRef != null && applicableRootPolicyRef != null && applicableRefPolicyRefs != null && features != null;

			this.features = features;
			this.rootPolicyRefExpression = new IdReferenceType(rootPolicyRef.getValue(), rootPolicyRef.getVersion(), null, null);
			this.applicableRootPolicyRef = new IdReferenceType(applicableRootPolicyRef.getValue(), applicableRootPolicyRef.getVersion(), null, null);
			this.applicableRefPolicyRefs = applicableRefPolicyRefs.stream().map(ref -> new IdReferenceType(ref.getValue(), ref.getVersion(), null, null)).collect(Collectors.toList());
			this.lastModified = lastModified;
		}

		@Override
		public List<PdpFeature> getFeatures()
		{
			return this.features;
		}

		@Override
		public IdReferenceType getRootPolicyRefExpression()
		{
			return rootPolicyRefExpression;
		}

		@Override
		public long getLastModified()
		{
			return this.lastModified;
		}

		@Override
		public IdReferenceType getApplicableRootPolicyRef()
		{
			return this.applicableRootPolicyRef;
		}

		@Override
		public List<IdReferenceType> getApplicableRefPolicyRefs()
		{
			return this.applicableRefPolicyRefs;
		}

	}

	/**
	 * Supported PDP feature type
	 */
	public enum PdpFeatureType
	{

		/**
		 * Features that are not related to extensions like the ones below, but to Authzforce PDP's core engine. Considered as the default type, if undefined.
		 */
		CORE("urn:ow2:authzforce:feature-type:pdp:core", null),

		/**
		 * XACML Attribute DataType extension, corresponding to Authzforce PDP engine's configuration element <i>attributeDatatype</i>
		 */
		DATATYPE("urn:ow2:authzforce:feature-type:pdp:data-type", AttributeValueFactory.class),

		/**
		 * XACML function extension, corresponding to Authzforce PDP engine's configuration element <i>function</i>
		 */
		FUNCTION("urn:ow2:authzforce:feature-type:pdp:function", Function.class),

		/**
		 * Policy/Rule combining algorithm extension, corresponding to Authzforce PDP engine's configuration element <i>combiningAlgorithm</i>
		 */
		COMBINING_ALGORITHM("urn:ow2:authzforce:feature-type:pdp:combining-algorithm", CombiningAlg.class),

		/**
		 * XACML Request preprocessor, corresponding to Authzforce PDP engine's configuration element <i>requestPreproc</i>
		 */
		REQUEST_PREPROC("urn:ow2:authzforce:feature-type:pdp:request-preproc", DecisionRequestPreprocessor.Factory.class),

		/**
		 * XACML Result postprocessor, corresponding to Authzforce Core PDP engine's configuration element <i>resultPostproc</i>
		 */
		RESULT_POSTPROC("urn:ow2:authzforce:feature-type:pdp:result-postproc", DecisionResultPostprocessor.Factory.class);

		private final Class<? extends PdpExtension> extensionClass;
		private final String id;

		PdpFeatureType(final String id, final Class<? extends PdpExtension> extensionClass)
		{
			assert id != null;
			this.id = id;
			this.extensionClass = extensionClass;
		}

		private static final Map<String, PdpFeatureType> ID_TO_FEATURE_MAP = Maps.uniqueIndex(Arrays.asList(PdpFeatureType.values()),
				input -> {
					assert input != null;
					return input.id;
				});

		@Override
		public String toString()
		{
			return this.id;
		}
	}

	private static final Pattern XACML_JSON_PDP_REQUEST_PREPROC_ID_PATTERN = Pattern.compile("^(.*\\W|)xacml-json(\\W.*|)$", Pattern.CASE_INSENSITIVE);

	/**
	 * Supported PDP core feature
	 */
	public enum PdpCoreFeature
	{
		/**
		 * Corresponds to Authzforce PDP engine's configuration attribute <i>enableXPath</i>
		 */
		XPATH_EVAL("urn:ow2:authzforce:feature:pdp:core:xpath-eval"),

		/**
		 * Corresponds to Authzforce PDP engine's configuration attribute <i>strictAttributeIssuerMatch</i>
		 */
		STRICT_ATTRIBUTE_ISSUER_MATCH("urn:ow2:authzforce:feature:pdp:core:strict-attribute-issuer-match");

		private final String id;

		PdpCoreFeature(final String id)
		{
			this.id = id;
		}

		private static PdpCoreFeature fromId(final String id)
		{
			for (final PdpCoreFeature f : PdpCoreFeature.values())
			{
				if (f.id.equals(id))
				{
					return f;
				}
			}

			return null;
		}

		@Override
		public String toString()
		{
			return this.id;
		}
	}

	private static final Map<PdpFeatureType, Set<String>> PDP_FEATURE_IDENTIFIERS_BY_TYPE = new EnumMap<>(PdpFeatureType.class);
	private static final int PDP_FEATURE_COUNT;

	static
	{
		// PDP core features
		final PdpCoreFeature[] pdpCoreFeatures = PdpCoreFeature.values();
		final Set<String> coreFeatureIDs = new HashSet<>(pdpCoreFeatures.length);
		for (final PdpCoreFeature f : pdpCoreFeatures)
		{
			coreFeatureIDs.add(f.id);
		}

		PDP_FEATURE_IDENTIFIERS_BY_TYPE.put(PdpFeatureType.CORE, Collections.unmodifiableSet(coreFeatureIDs));
		int featureCount = coreFeatureIDs.size();

		// PDP extensions
		for (final PdpFeatureType featureType : PdpFeatureType.values())
		{
			if (featureType.extensionClass != null)
			{
				final Set<String> extIDs = PdpExtensions.getNonJaxbBoundExtensionIDs(featureType.extensionClass);
				PDP_FEATURE_IDENTIFIERS_BY_TYPE.put(featureType, extIDs);
				featureCount += extIDs.size();
			}
		}

		PDP_FEATURE_COUNT = featureCount;
	}

	private static final DecisionRequestPreprocessor.Factory<Request, IndividualXacmlJaxbRequest> DEFAULT_XACML_XML_DECISION_REQUEST_PREPROC_FACTORY = SingleDecisionXacmlJaxbRequestPreprocessor.LaxVariantFactory.INSTANCE;
	private static final DecisionRequestPreprocessor.Factory<JSONObject, IndividualXacmlJsonRequest> DEFAULT_XACML_JSON_DECISION_REQUEST_PREPROC_FACTORY = SingleDecisionXacmlJsonRequestPreprocessor.LaxVariantFactory.INSTANCE;

	private static final UnsupportedOperationException NULL_PDP_ERROR = new UnsupportedOperationException("PDP internal error. Contact the system or domain administrator.");

	/**
	 * Initializes a UUID generator that generates UUID version 1. It is thread-safe and uses the host MAC address as the node field if useRandomAddressBasedUUID = false, in which case UUID uniqueness
	 * across multiple hosts (e.g. in a High-Availability architecture) is guaranteed. If this is used by multiple hosts to generate UUID for common objects (e.g. in a High Availability architecture),
	 * it is critical that clocks of all hosts be synchronized (e.g. with a common NTP server). If no MAC address is available, e.g. no network connection, set useRandomAddressBasedUUID = true to use
	 * a random multicast address instead as node field.
	 * 
	 * @see <a href= "http://www.cowtowncoder.com/blog/archives/2010/10/entry_429.html"> More on Java UUID Generator (JUG), a word on performance</a>
	 * @see <a href= "http://johannburkard.de/blog/programming/java/Java-UUID-generators-compared.html"> Java UUID generators compared</a>
	 * 
	 * @return UUID v1
	 */
	private static TimeBasedGenerator initUUIDGenerator(final boolean useRandomAddressBasedUUID)
	{

		final EthernetAddress macAddress;
		if (useRandomAddressBasedUUID)
		{
			macAddress = EthernetAddress.constructMulticastAddress();
		}
		else
		{
			macAddress = EthernetAddress.fromInterface();
			if (macAddress == null)
			{
				throw new RuntimeException(
				        "Failed to create UUID generator (based on time and MAC address): no valid Ethernet MAC address found. Please enable at least one network interface for global uniqueness of UUIDs. If not, you can fall back to UUID generation based on random multicast address instead by setting argument: useRandomAddressBasedUUID = true");
			}
		}

		return Generators.timeBasedGenerator(macAddress);
	}

	private static final class PdpBundle
	{
		private final CloseablePdpEngine engine;
		private final PdpEngineInoutAdapter<Request, Response> xacmlJaxbIoAdapter;
		private final PdpEngineInoutAdapter<JSONObject, JSONObject> xacmlJsonIoAdapter;

		private PdpBundle(final PdpEngineConfiguration pdpConf, final boolean enableXacmlJsonProfile) throws IllegalArgumentException, IOException
		{
			this.engine = new BasePdpEngine(pdpConf);
			// did not throw exception, so valid
			/*
			 * Check that all policies used by PDP are statically resolved Indeed, dynamic policy resolution is not supported by this PAP DAO implementation
			 */
			final Iterable<PrimaryPolicyMetadata> pdpApplicablePolicies = engine.getApplicablePolicies();
			if (pdpApplicablePolicies == null)
			{
				this.engine.close();
				throw ILLEGAL_POLICY_NOT_STATIC_EXCEPTION;
			}

			/*
			 * PDP input/output adapters
			 */
			final Map<Class<?>, Entry<DecisionRequestPreprocessor<?, ?>, DecisionResultPostprocessor<?, ?>>> ioProcChains = pdpConf.getInOutProcChains();
			final int clientReqErrVerbosityLevel = pdpConf.getClientRequestErrorVerbosityLevel();
			final AttributeValueFactoryRegistry attValFactoryRegistry = pdpConf.getAttributeValueFactoryRegistry();
			final boolean isStrictAttIssuerMatchEnabled = pdpConf.isStrictAttributeIssuerMatchEnabled();
			final boolean isXpathEnabled = pdpConf.isXPathEnabled();

			/*
			 * XACML/XML (JAXB) request/response adapter
			 */
			final DecisionRequestPreprocessorSupplier defaultXacmlXmlReqPreprocSupplier = extraPdpFeatures -> DEFAULT_XACML_XML_DECISION_REQUEST_PREPROC_FACTORY.getInstance(attValFactoryRegistry, isStrictAttIssuerMatchEnabled, isXpathEnabled, extraPdpFeatures);
			final Supplier<DecisionResultPostprocessor<?, ?>> defaultXacmlXmlResultPostproc = () -> new BaseXacmlJaxbResultPostprocessor(clientReqErrVerbosityLevel);
			this.xacmlJaxbIoAdapter = PdpEngineAdapters.newInoutAdapter(Request.class, Response.class, engine, ioProcChains, defaultXacmlXmlReqPreprocSupplier, defaultXacmlXmlResultPostproc);

			/*
			 * XACML/JSON request/response adapter
			 */
			if (enableXacmlJsonProfile)
			{
				final DecisionRequestPreprocessorSupplier defaultXacmlJsonReqPreprocSupplier = extraPdpFeatures -> DEFAULT_XACML_JSON_DECISION_REQUEST_PREPROC_FACTORY.getInstance(attValFactoryRegistry, isStrictAttIssuerMatchEnabled, isXpathEnabled,
						extraPdpFeatures);
				final Supplier<DecisionResultPostprocessor<?, ?>> defaultXacmlJsonResultPostproc = () -> new BaseXacmlJsonResultPostprocessor(clientReqErrVerbosityLevel);
				this.xacmlJsonIoAdapter = PdpEngineAdapters.newInoutAdapter(JSONObject.class, JSONObject.class, engine, ioProcChains, defaultXacmlJsonReqPreprocSupplier,
				        defaultXacmlJsonResultPostproc);
			}
			else
			{
				this.xacmlJsonIoAdapter = null;
			}
		}

		private boolean isXacmlXmlSupportEnabled()
		{
			return xacmlJaxbIoAdapter != null;
		}

		private boolean isXacmlJsonSupportEnabled()
		{
			return xacmlJsonIoAdapter != null;
		}

		private Response evaluate(final Request request)
		{
			assert xacmlJaxbIoAdapter != null;
			return xacmlJaxbIoAdapter.evaluate(request);
		}

		private JSONObject evaluate(final JSONObject request)
		{
			if (xacmlJsonIoAdapter == null)
			{
				throw UNSUPPORTED_XACML_JSON_PROFILE_OPERATION_EXCEPTION;
			}

			return xacmlJsonIoAdapter.evaluate(request);
		}

	}

	private final TimeBasedGenerator uuidGen;

	private final Path domainsRootDir;

	/**
	 * Maps domainId to domain
	 */
	private final ConcurrentMap<String, DOMAIN_DAO_CLIENT> domainMap = new ConcurrentHashMap<>();

	/**
	 * Maps domain externalId to unique API-defined domainId in domainMap keys
	 */
	private final ConcurrentMap<String, String> domainIDsByExternalId = new ConcurrentHashMap<>();

	private final Path domainTmplDirPath;

	private final PdpModelHandler pdpModelHandler;

	private final long domainDirToMemSyncIntervalSec;

	private final DomainDaoClient.Factory<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT, FlatFileBasedDomainDao<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT>, DOMAIN_DAO_CLIENT> domainDaoClientFactory;

	private final boolean enablePdpOnly;

	private final boolean enableXacmlJsonProfile;

	private final PolicyDaoClient.Factory<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT> policyDaoClientFactory;

	private final PolicyVersionDaoClient.Factory<VERSION_DAO_CLIENT> policyVersionDaoClientFactory;

	/**
	 * Must be called this method in a block synchronized on 'domainsRootDir'
	 * 
	 * @param domainId
	 *            ID of domain to be removed
	 */
	private synchronized void removeDomainFromCache(final String domainId) throws IOException
	{
		/*
		 * Assumed called within synchronized(domainsRootDir) block
		 */
		assert domainId != null;
		final DOMAIN_DAO_CLIENT domain = domainMap.remove(domainId);
		if (domain == null)
		{
			// already removed
			return;
		}

		try (FlatFileBasedDomainDao<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT> domainDAO = domain.getDao())
		{
			final String externalId = domainDAO.getExternalId();
			if (externalId != null)
			{
				domainIDsByExternalId.remove(externalId);
			}
		}
	}

	private final class FileBasedDomainDaoImpl implements FlatFileBasedDomainDao<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT>
	{

		private final String domainId;

		private final Path domainDirPath;

		private final File propertiesFile;

		private final File pdpConfFile;

		private final Path policyParentDirPath;

		private final DefaultEnvironmentProperties pdpConfEnvProps;

		private final SuffixMatchingDirectoryStreamFilter policyFilePathFilter;

		private final ScheduledExecutorService dirToMemSyncScheduler;

		/*
		 * Last time when external ID in domain maps was synced with repository (properties file in domain directory (set respectively by saveProperties() and loadProperties() methods only)
		 */
		private volatile long propertiesFileLastSyncedTime = 0;

		private volatile String cachedExternalId = null;

		private volatile PdpBundle pdp = null;

		/**
		 * Do not make it static (STCAL_INVOKE_ON_STATIC_DATE_FORMAT_INSTANCE raised by spotbugs then) because not thread-safe
		 */
		private final DateFormat utcDateWithMillisFormatter;

		/*
		 * Last time when PDP was (re)loaded from repository (pdp conf and policy files in domain directory) (set only by reloadPDP)
		 */
		private volatile long lastPdpSyncedTime = 0;

		@Override
		public DomainProperties sync() throws IOException, IllegalArgumentException
		{
			/*
			 * synchronized block makes sure no other thread is messing with the domain directory while we synchronize it to domainMap. See also method #add(Properties)
			 */
			final DomainProperties props;
			synchronized (domainsRootDir)
			{
				LOGGER.debug("Domain '{}': synchronizing...", domainId);
				if (Files.notExists(domainDirPath, LinkOption.NOFOLLOW_LINKS))
				{
					// DOMAIN DIRECTORY REMOVED
					LOGGER.info("Domain '{}' removed from filesystem -> removing from cache", domainId);
					removeDomainFromCache(domainId);
					return null;
				}

				// SYNC DOMAIN DIRECTORY
				props = syncDomainProperties(false);
				final boolean isChanged = syncPDP();
				if (isChanged)
				{
					LOGGER.info("Domain '{}': synchronization: change to PDP files since last sync -> PDP reloaded", domainId);
				}

				LOGGER.debug("Domain '{}': synchronization done.", domainId);
			}

			return props;
		}

		/**
		 * this is run by domainDirToMemSyncScheduler
		 */
		private final class DirectoryToMemorySyncTask implements Runnable
		{
			@Override
			public void run()
			{
				try
				{
					sync();

				} catch (final Throwable e)
				{
					LOGGER.error("Domain '{}': error occurred during synchronization", domainId, e);
				}
			}
		}

		/**
		 * Constructs end-user policy admin domain. Must be called must use synchronized (domainsRootDir) block.
		 *
		 * @param domainDirPath domain directory
		 * @param props         new domain properties for new domain creation, null if no specific properties (use default properties)
		 * @throws IllegalArgumentException Invalid configuration files in {@code domainDir}
		 * @throws IOException              Error loading configuration file(s) from or persisting {@code props} (if not null) to {@code domainDir}
		 */
		private FileBasedDomainDaoImpl(final Path domainDirPath, final WritableDomainProperties props) throws IOException
		{
			assert domainDirPath != null;

			final Path domainFileName = domainDirPath.getFileName();
			if (domainFileName == null)
			{
				throw new IllegalArgumentException("Invalid domain directory path: " + domainDirPath);
			}

			this.domainId = domainFileName.toString();

			// domainDir
			FlatFileDAOUtils.checkFile("Domain directory", domainDirPath, true, true);
			this.domainDirPath = domainDirPath;

			/*
			 * PDP configuration parser environment properties, e.g. PARENT_DIR for replacement in configuration strings
			 */
			this.pdpConfEnvProps = new DefaultEnvironmentProperties(Collections.singletonMap(EnvironmentPropertyName.PARENT_DIR, domainDirPath.toUri().toString()));

			// PDP config file
			this.pdpConfFile = domainDirPath.resolve(DOMAIN_PDP_CONFIG_FILENAME).toFile();

			/*
			 * Get policy directory from PDP conf (policyProvider/policyLocation pattern)
			 */
			final Pdp pdpConf = loadPDPConfTmpl();

			/*
			 * Get the policies parent directory and suffix from PDP config (policyProvider)
			 */
			final List<AbstractPolicyProvider> policyProviders = pdpConf.getPolicyProviders();
			final AbstractPolicyProvider policyProvider;
			if (policyProviders.size() != 1 || !((policyProvider = policyProviders.get(0)) instanceof StaticFlatFileDaoPolicyProviderDescriptor))
			{
				// critical error
				throw new RuntimeException("Invalid PDP configuration of domain '" + domainId + "' in file '" + pdpConfFile + "': there is not exactly one policyProvider or it is not an instance of "
						+ StaticFlatFileDaoPolicyProviderDescriptor.class + " as expected.");
			}

			final StaticFlatFileDaoPolicyProviderDescriptor fileBasedPolicyProvider = (StaticFlatFileDaoPolicyProviderDescriptor) policyProvider;
			// replace any ${PARENT_DIR} placeholder in policy location pattern
			final String policyLocation = pdpConfEnvProps.replacePlaceholders(fileBasedPolicyProvider.getPolicyLocationPattern());
			final Entry<Path, String> result = FlatFileDaoPolicyProvider.validateConf(policyLocation);
			this.policyParentDirPath = result.getKey();
			FlatFileDAOUtils.checkFile("Domain policies directory", policyParentDirPath, true, true);

			final String policyFilenameSuffix = result.getValue();
			this.policyFilePathFilter = new FlatFileDAOUtils.SuffixMatchingDirectoryStreamFilter(policyFilenameSuffix);

			// Date formatter is used by updateDomainProperties(...) so must be initialized before calling updateDomainProperties() down below
			if (LOGGER.isDebugEnabled())
			{
				utcDateWithMillisFormatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS ('UTC')");
				utcDateWithMillisFormatter.setTimeZone(TimeZone.getTimeZone("UTC"));
			} else
			{
				utcDateWithMillisFormatter = null;
			}

			// propFile
			this.propertiesFile = domainDirPath.resolve(DOMAIN_PROPERTIES_FILENAME).toFile();

			/*
			 * Set propertiesFileLastSyncedTime based on propertilesFile lastmodified, validate and reload domain properties file; in particular, sync externalId from propertiesFile to the externalId
			 * in the externalId-to-domainId map
			 */
			/*
			 * Caller must use synchronized (domainsRootDir) block
			 */
			updateDomainProperties(props);

			// Just load the PDP from the files
			reloadPDP();

			/*
			 * Schedule periodic domain directory-to-memory synchronization task if sync enabled (strictly positive interval defined)
			 */
			if (domainDirToMemSyncIntervalSec > 0)
			{
				// Sync enabled
				final DirectoryToMemorySyncTask syncTask = new DirectoryToMemorySyncTask();
				dirToMemSyncScheduler = Executors.newScheduledThreadPool(1);
				dirToMemSyncScheduler.scheduleWithFixedDelay(syncTask, domainDirToMemSyncIntervalSec, domainDirToMemSyncIntervalSec, TimeUnit.SECONDS);
				LOGGER.info("Domain '{}': scheduled periodic directory-to-memory synchronization (initial delay={}s, period={}s)", domainId, domainDirToMemSyncIntervalSec,
						domainDirToMemSyncIntervalSec);
			} else
			{
				dirToMemSyncScheduler = null;
			}

		}

		@Override
		public String getDomainId()
		{
			return this.domainId;
		}

		@Override
		public String getExternalId()
		{
			return this.cachedExternalId;
		}

		/**
		 * Reload PDP from configuration files, (including policy files, aka "PRP" in XACML). This method first sets lastPdpSyncedTime to the current time.
		 *
		 * @throws IOException              I/O error reading from confFile
		 * @throws IllegalArgumentException Invalid PDP configuration in confFile
		 */
		private void reloadPDP() throws IOException, IllegalArgumentException
		{
			lastPdpSyncedTime = System.currentTimeMillis();
			// test if PDP conf valid, and update the domain's PDP only if valid
			final PdpEngineConfiguration pdpEngineConf = PdpEngineConfiguration.getInstance(pdpConfFile, pdpModelHandler);
			final PdpBundle newPdpBundle = new PdpBundle(pdpEngineConf, enableXacmlJsonProfile);
			// update the domain's PDP
			if (pdp != null && pdp.engine != null)
			{
				pdp.engine.close();
			}

			pdp = newPdpBundle;
		}

		/**
		 * Reload PDP with input JAXB conf, and persist conf to file if PDP reloaded successfully
		 *
		 * @param pdpConfTmpl original PDP configuration template from file, i.e. before any replacement of property placeholders like ${PARENT_DIR}; saved/marshalled to file PDP update succeeds
		 * @throws IllegalArgumentException invalid pdpConfTmpl
		 * @throws IOException              I/0 error with Attribute/Policy provider in pdpConfTmpl
		 */
		private void reloadPDP(final Pdp pdpConfTmpl) throws IllegalArgumentException, IOException
		{
			// test if PDP conf valid, and update the domain's PDP only if valid
			final PdpEngineConfiguration pdpEngineConf = new PdpEngineConfiguration(pdpConfTmpl, pdpConfEnvProps);
			final PdpBundle newPdpBundle = new PdpBundle(pdpEngineConf, enableXacmlJsonProfile);
			// Commit/save the new PDP conf
			try
			{
				pdpModelHandler.marshal(pdpConfTmpl, pdpConfFile);
			} catch (final JAXBException e)
			{
				// critical error: we should not end up with an invalid PDP
				// configuration file, so we consider an I/O error
				throw new IOException("Error writing new PDP configuration of domain '" + domainId + "'", e);
			}

			// update the domain's PDP
			if (pdp != null && pdp.engine != null)
			{
				pdp.engine.close();
			}

			pdp = newPdpBundle;
		}

		private void setPdpInErrorState() throws IOException
		{
			if (pdp != null && pdp.engine != null)
			{
				pdp.engine.close();
			}

			pdp = null;
		}

		private void saveProperties(final DomainProperties props) throws IOException
		{
			final Marshaller marshaller;
			try
			{
				marshaller = DOMAIN_PROPERTIES_JAXB_CONTEXT.createMarshaller();
				marshaller.setProperty(Marshaller.JAXB_ENCODING, StandardCharsets.UTF_8.name());
			} catch (final JAXBException e)
			{
				// critical error
				throw new RuntimeException("Error creating JAXB unmarshaller for domain properties (XML)", e);
			}

			marshaller.setSchema(DOMAIN_PROPERTIES_SCHEMA);
			try
			{
				/*
				 * The rootPolicyRef is in another file (PDP configuration file). We cannot marshall more generic ManagedResourceProperties because it does not have
				 *
				 * @XmlRootElement
				 */
				marshaller.marshal(props, propertiesFile);
			} catch (final JAXBException e)
			{
				throw new IOException("Error persisting properties (XML) of domain '" + domainId + "'", e);
			}
		}

		private DomainProperties loadProperties() throws IOException
		{
			final Unmarshaller unmarshaller;
			try
			{
				unmarshaller = DOMAIN_PROPERTIES_JAXB_CONTEXT.createUnmarshaller();
			} catch (final JAXBException e)
			{
				// critical error
				throw new RuntimeException("Error creating JAXB unmarshaller for domain properties (XML)", e);
			}

			unmarshaller.setSchema(DOMAIN_PROPERTIES_SCHEMA);
			final JAXBElement<DomainProperties> jaxbElt;
			try
			{
				jaxbElt = unmarshaller.unmarshal(new StreamSource(propertiesFile), DomainProperties.class);
			} catch (final JAXBException e)
			{
				throw new IOException("Error getting properties (XML) of domain '" + domainId + "'", e);
			}

			return jaxbElt.getValue();
		}

		/**
		 * Update externalId (cached value) and external-id-to-domain map. The caller must call this within a {@code synchronized(domainsRootDir)} block in which it guarantees the synchronization
		 * between the domain's {@code newExternalId} and the externalId value in the domain properties on the filesystem. This method updates the externalId value only in the externalId-domainId
		 * cache/map.
		 *
		 * @param newExternalId new domain's externalId; null value means to unset the domain's externalId (undefined)
		 * @throws IllegalArgumentException if {@code newExternalId != null} and {@code newExternalId} is already associated with another domainId (conflict), i.e. {@code domainIDsByExternalId.containsKey(newExternalId)}
		 */
		private void updateCachedExternalId(final String newExternalId) throws IllegalArgumentException
		{
			if (cachedExternalId != null)
			{
				if (cachedExternalId.equals(newExternalId))
				{
					// nothing changed
					return;
				}

				/*
				 * externalId changed -> remove the old one from externalId-domainId map
				 */
				domainIDsByExternalId.remove(cachedExternalId);
			}

			if (newExternalId != null)
			{
				final String alreadyAssociatedDomainId = domainIDsByExternalId.putIfAbsent(newExternalId, domainId);
				if (alreadyAssociatedDomainId != null)
				{
					throw new IllegalArgumentException("externalId conflict: '" + newExternalId + "' cannot be associated with domainId '" + domainId + "' because already associated with another");
				}
			}

			cachedExternalId = newExternalId;
		}

		/**
		 * Update domain properties from input {@code props} and/or from changes on the filesystem and synchronize with cached data (e.g. cachedExternalId, externalId-domainId map (if externalId
		 * changed), etc.). Must be called within a {@code synchronized(domainsRootDir)} block
		 *
		 * @param props new domain properties; if null, sync with properties file on the filesystem only
		 * @throws IOException I/O error reading/writing properties on the filesystem
		 */
		private void updateDomainProperties(final WritableDomainProperties props) throws IOException
		{
			/*
			 * DomainProperties on the filesystem may contain other properties (e.g. PRP properties) than the ones in props, so we must preserve them
			 */
			if (props != null)
			{
				/*
				 * Check whether externalId already used if changed
				 */
				final String newExternalId = props.getExternalId();
				if (newExternalId != null && !newExternalId.equals(this.cachedExternalId) && domainIDsByExternalId.containsKey(newExternalId))
				{
					throw new IllegalArgumentException("externalId conflict: '" + newExternalId + "' cannot be associated with domainId '" + domainId + "' because already associated with another");
				}

				// set/save properties
				final DomainProperties updatedProps = loadProperties();
				updatedProps.setDescription(props.getDescription());
				updatedProps.setExternalId(props.getExternalId());

				// validate and save new properties to disk
				saveProperties(updatedProps);
				/*
				 * sync properties file with memory (e.g. externalId-domainId map). Must be called within domainsRootDir block.
				 */
				syncDomainProperties(true);
			} else
			{
				syncDomainProperties(false);
			}
		}

		@Override
		public ReadableDomainProperties setDomainProperties(final WritableDomainProperties props) throws IOException, IllegalArgumentException
		{
			if (enablePdpOnly)
			{
				throw DISABLED_OPERATION_EXCEPTION;
			}

			if (props == null)
			{
				throw NULL_DOMAIN_PROPERTIES_ARGUMENT_EXCEPTION;
			}

			synchronized (domainsRootDir)
			{
				updateDomainProperties(props);
			}

			return new ReadableDomainPropertiesImpl(domainId, props.getDescription(), props.getExternalId());

		}

		/**
		 * Must be called within synchronized(domainsRootDir) block.
		 *
		 * @param force force synchronization regardless of lastmodified timestamp on properties file, esp. when we know we just made/detected a change
		 */
		private DomainProperties syncDomainProperties(final boolean force) throws IOException
		{
			final long lastModifiedTime = propertiesFile.lastModified();
			final boolean isFileModified = lastModifiedTime > propertiesFileLastSyncedTime;
			if (LOGGER.isDebugEnabled())
			{
				LOGGER.debug("Domain '{}': domain properties file '{}': lastModifiedTime (= {}) {} last sync time (= {}){}", domainId, propertiesFile,
						utcDateWithMillisFormatter.format(new Date(lastModifiedTime)), isFileModified ? ">" : "<=", utcDateWithMillisFormatter.format(new Date(propertiesFileLastSyncedTime)),
						isFileModified ? " -> updating externalId in externalId-to-domain map" : "");
			}

			// let's sync
			propertiesFileLastSyncedTime = System.currentTimeMillis();
			final DomainProperties props = loadProperties();
			if (force || isFileModified)
			{
				/*
				 * Must be called within synchronized(domainsRootDir) block
				 */
				updateCachedExternalId(props.getExternalId());
			}

			return props;
		}

		@Override
		public ReadableDomainProperties getDomainProperties() throws IOException
		{
			if (enablePdpOnly)
			{
				throw DISABLED_OPERATION_EXCEPTION;
			}

			final DomainProperties props;
			synchronized (domainsRootDir)
			{
				props = syncDomainProperties(false);
			}

			return new ReadableDomainPropertiesImpl(domainId, props.getDescription(), props.getExternalId());
		}

		@Override
		public boolean isPapEnabled()
		{
			return !enablePdpOnly;
		}

		/**
		 * Loads original PDP configuration template from file, before any replacement of property placeholders like ${PARENT_DIR}
		 *
		 * @return original PDP configuration from file (no property like PARENT_DIR replaced in the process)
		 * @throws IOException I/O error with Attribute/Policy provider
		 */
		private Pdp loadPDPConfTmpl() throws IOException
		{
			try
			{
				return pdpModelHandler.unmarshal(new StreamSource(pdpConfFile), Pdp.class);
			} catch (final JAXBException e)
			{
				// critical error: we should not end up with an invalid PDP
				// configuration file, so we consider an I/O error
				throw new IOException("Error reading PDP configuration of domain '" + domainId + "'", e);
			}
		}

		/**
		 * Sync PDP's applicable policies in memory with the policy repository on the filesystem
		 *
		 * @return true iff the PDP was reloaded during the process, i.e. if some change to policy files was found
		 * @throws IllegalArgumentException invalid policies on the filesystem
		 * @throws IOException              I/O error accessing policies on the filesystem
		 */
		private boolean syncPdpPolicies() throws IllegalArgumentException, IOException
		{
			if (pdp == null || pdp.engine == null)
			{
				// pdp in error state
				return false;
			}

			final Iterable<PrimaryPolicyMetadata> pdpApplicablePolicies = pdp.engine.getApplicablePolicies();
			if (pdpApplicablePolicies == null)
			{
				throw NON_STATIC_POLICY_EXCEPTION;
			}

			for (final PrimaryPolicyMetadata usedPolicyMetadata : pdpApplicablePolicies)
			{
				/*
				 * Check whether there is any change to the directory of this policy, in which case we have to reload the PDP to take any account any new version that might match the direct/indirect
				 * policy references from the root policy
				 */
				final String policyId = usedPolicyMetadata.getId();
				final Path policyDir = getPolicyDirectory(policyId);
				if (!Files.exists(policyDir, LinkOption.NOFOLLOW_LINKS))
				{
					// used policy file has been removed, this is a significant
					// change
					try
					{
						reloadPDP();
					} catch (final Throwable t)
					{
						/*
						 * a critical error occurred, maybe because the deleted policy is still referenced by the root policy anyway, this means the PDP configuration or policies in the domain
						 * directory are in a bad state
						 */
						setPdpInErrorState();
						throw new RuntimeException("Unrecoverable error occurred when reloading the PDP after detecting the removal of a policy ('" + policyId
								+ "') - previously used by the PDP - from the backend domain repository. Setting the PDP in error state until following errors are fixed by the administrator and the PDP re-synced via the PAP API",
								t);
					}

					return true;
				}

				// used policy file is there, checked whether changed since last
				// sync
				final long lastModifiedTime = Files.getLastModifiedTime(policyDir, LinkOption.NOFOLLOW_LINKS).toMillis();
				final boolean isFileModified = lastModifiedTime > lastPdpSyncedTime;
				if (LOGGER.isDebugEnabled())
				{
					LOGGER.debug("Domain '{}': policy '{}': file '{}': lastModifiedTime (= {}) {} last sync time (= {}){}", domainId, policyId, policyDir,
							utcDateWithMillisFormatter.format(new Date(lastModifiedTime)), isFileModified ? ">" : "<=", utcDateWithMillisFormatter.format(new Date(lastPdpSyncedTime)),
							isFileModified ? " -> reloading PDP" : "");
				}

				if (isFileModified)
				{
					try
					{
						reloadPDP();
					} catch (final Throwable t)
					{
						/*
						 * a critical error occurred, maybe because the deleted policy is still referenced by the root policy anyway, this means the PDP configuration or policies in the domain
						 * directory are in a bad state
						 */
						setPdpInErrorState();
						throw new RuntimeException("Unrecoverable error occurred when reloading the PDP after detecting a change to the policy ('" + policyId
								+ "') - used by the PDP - in the backend domain repository. Setting the PDP in error state until following errors are fixed by the administrator and the PDP re-synced via the PAP API",
								t);
					}

					return true;
				}
			}

			return false;
		}

		/**
		 * Reload PDP only if a change to one of PDP files (main configuration, policies...) has been detected. Should be called inside a synchronized(domainDirPath) block
		 *
		 * @return true iff PDP was actually changed by synchronization (reloaded)
		 * @throws IOException              I/O error accessing policies in the policy repository
		 * @throws IllegalArgumentException invalid policies in the policy repository
		 */
		private boolean syncPDP() throws IllegalArgumentException, IOException
		{
			// Check for change in PDP's main conf file
			final long lastModifiedTime = pdpConfFile.lastModified();
			final boolean isFileModified = lastModifiedTime > lastPdpSyncedTime;
			if (LOGGER.isDebugEnabled())
			{
				LOGGER.debug("Domain '{}': PDP conf file '{}': lastModifiedTime (= {}) {} last sync time (= {}){}", domainId, pdpConfFile,
						utcDateWithMillisFormatter.format(new Date(lastModifiedTime)), isFileModified ? ">" : "<=", utcDateWithMillisFormatter.format(new Date(lastPdpSyncedTime)),
						isFileModified ? " -> reloading PDP" : "");
			}

			if (isFileModified)
			{
				reloadPDP();
				return true;
			}

			// check for changes in PDP active policies
			return syncPdpPolicies();
		}

		/**
		 * @return list of static policy references, the first one is always the root policy reference, others - if any - are policy references from the root policy (direct or indirect)
		 */
		private List<TopLevelPolicyElementRef> getPdpApplicablePolicyRefs()
		{
			if (pdp == null || pdp.engine == null)
			{
				// pdp in error state
				throw PDP_IN_ERROR_STATE_RUNTIME_EXCEPTION;
			}

			final Iterable<PrimaryPolicyMetadata> pdpApplicablePolicies = pdp.engine.getApplicablePolicies();
			if (pdpApplicablePolicies == null)
			{
				throw NON_STATIC_POLICY_EXCEPTION;
			}

			final List<TopLevelPolicyElementRef> staticPolicyRefs = new ArrayList<>();
			pdpApplicablePolicies.forEach(policyMeta -> staticPolicyRefs.add(new TopLevelPolicyElementRef(policyMeta.getId(), policyMeta.getVersion().toString(), true)));
			return staticPolicyRefs;
		}

		private List<PdpFeature> getPdpFeatures(final Pdp pdpConf)
		{
			final List<PdpFeature> features = new ArrayList<>(PDP_FEATURE_COUNT);
			for (final PdpFeatureType featureType : PdpFeatureType.values())
			{
				final Set<String> enabledFeatures;
				switch (featureType)
				{
					case CORE:
						final PdpCoreFeature[] coreFeatures = PdpCoreFeature.values();
						enabledFeatures = HashCollections.newUpdatableSet(coreFeatures.length);
						for (final PdpCoreFeature coreFeature : coreFeatures)
						{
							switch (coreFeature)
							{
								case XPATH_EVAL:
									if (pdpConf.isXPathEnabled())
									{
										enabledFeatures.add(coreFeature.id);
									}
									break;
								case STRICT_ATTRIBUTE_ISSUER_MATCH:
									if (pdpConf.isStrictAttributeIssuerMatch())
									{
										enabledFeatures.add(coreFeature.id);
									}
									break;
								default:
									throw new UnsupportedOperationException("Unsupported PDP CORE feature: " + coreFeature.id);
							}
						}

						break;

					case DATATYPE:
						enabledFeatures = HashCollections.newImmutableSet(pdpConf.getAttributeDatatypes());
						break;

					case FUNCTION:
						enabledFeatures = HashCollections.newImmutableSet(pdpConf.getFunctions());
						break;

					case COMBINING_ALGORITHM:
						enabledFeatures = HashCollections.newImmutableSet(pdpConf.getCombiningAlgorithms());
						break;

					case REQUEST_PREPROC:
						enabledFeatures = pdpConf.getIoProcChains().stream().map(InOutProcChain::getRequestPreproc).filter(Objects::nonNull).collect(Collectors.toSet());
						/*
						 * Add default ones if no else defined for same type of input
						 */
						if (enabledFeatures.isEmpty())
						{

							enabledFeatures.add(DEFAULT_XACML_XML_DECISION_REQUEST_PREPROC_FACTORY.getId());
							if (enableXacmlJsonProfile)
							{
								enabledFeatures.add(DEFAULT_XACML_JSON_DECISION_REQUEST_PREPROC_FACTORY.getId());
							}
						} else if (enabledFeatures.size() < 2 && enableXacmlJsonProfile)
						{
							final String enabledReqPreprocId = enabledFeatures.iterator().next();
							/*
							 * Which type of request preproc is it? If it matches the pattern for XACML/JSON request preprocs, is is a XACML/JSON one, else XACML/XML. If XACML/JSON preproc already
							 * enabled, only add the default XACML/XML to the set, else the opposite.
							 *
							 * TODO: find a more reliable way to identify the type of preproc
							 */
							enabledFeatures.add(XACML_JSON_PDP_REQUEST_PREPROC_ID_PATTERN.matcher(enabledReqPreprocId).matches() ? DEFAULT_XACML_XML_DECISION_REQUEST_PREPROC_FACTORY.getId()
									: DEFAULT_XACML_JSON_DECISION_REQUEST_PREPROC_FACTORY.getId());
						}
						break;

					case RESULT_POSTPROC:
						enabledFeatures = pdpConf.getIoProcChains().stream().map(InOutProcChain::getResultPostproc).filter(Objects::nonNull).collect(Collectors.toSet());
						break;

					default:
						throw new UnsupportedOperationException("Unsupported PDP feature type: " + featureType);
				}

				final Set<String> disabledFeatures = new HashSet<>(PDP_FEATURE_IDENTIFIERS_BY_TYPE.get(featureType));
				for (final String featureId : enabledFeatures)
				{
					features.add(new PdpFeature(featureId, featureType.id, true));
					disabledFeatures.remove(featureId);
				}

				for (final String disabledFeatureID : disabledFeatures)
				{
					features.add(new PdpFeature(disabledFeatureID, featureType.id, false));
				}
			} // END Collect PDP features

			return features;
		}

		@Override
		public ReadablePdpProperties setOtherPdpProperties(final WritablePdpProperties properties) throws IOException, IllegalArgumentException
		{
			if (enablePdpOnly)
			{
				throw DISABLED_OPERATION_EXCEPTION;
			}

			if (properties == null)
			{
				throw NULL_PDP_PROPERTIES_ARGUMENT_EXCEPTION;
			}

			final IdReferenceType newRootPolicyRefExpression = properties.getRootPolicyRefExpression();
			if (newRootPolicyRefExpression == null)
			{
				throw NULL_ROOT_POLICY_REF_ARGUMENT_EXCEPTION;
			}

			synchronized (domainDirPath)
			{
				final long pdpConfLastSyncTime = System.currentTimeMillis();
				/*
				 * Get current PDP conf that we have to change (only part of it)
				 */
				final Pdp pdpConf = loadPDPConfTmpl();

				/*
				 * let's change the PDP configuration
				 */
				lastPdpSyncedTime = pdpConfLastSyncTime;

				// PDP features
				// reset features
				boolean enableXPath = false;
				boolean enableStrictAttIssuerMatch = false;
				/*
				 * Default I/O processing chain will be applied (with default request/result pre/postprocessors) if none in configuration
				 */
				final List<InOutProcChain> newIoProcChains = new ArrayList<>();
				final List<String> newAttDatatypes = new ArrayList<>();
				final List<String> newCombiningAlgs = new ArrayList<>();
				final List<String> newPdpFunctions = new ArrayList<>();

				/*
				 * BEGIN COLLECT INPUT FEATURES validate/canonicalize input PDP features, making sure all extensions are listed only once per ID, with a defined type and enabled=true/false
				 */
				final List<PdpFeature> inputFeatures = properties.getFeatures();
				final Set<String> featureIDs = new HashSet<>(inputFeatures.size());
				final Map<Class<?>, DecisionRequestPreprocessor.Factory<?, ?>> reqPreprocFactoriesByInputType = HashCollections.newUpdatableMap(inputFeatures.size());
				final Map<Class<?>, String> resultProcIdentifiersByInputType = HashCollections.newUpdatableMap(inputFeatures.size());

				for (final PdpFeature feature : properties.getFeatures())
				{
					final String featureID = feature.getId();
					if (featureID == null)
					{
						throw INVALID_FEATURE_ID_EXCEPTION;
					}

					final String inputFeatureTypeId = feature.getType();
					final PdpFeatureType nonNullFeatureType;

					// CORE is the default feature type if type undefined
					if (inputFeatureTypeId == null)
					{
						nonNullFeatureType = PdpFeatureType.CORE;
					} else
					{
						nonNullFeatureType = PdpFeatureType.ID_TO_FEATURE_MAP.get(inputFeatureTypeId);
						if (nonNullFeatureType == null)
						{
							throw new IllegalArgumentException("Invalid feature type: '" + inputFeatureTypeId + "'. Expected: " + PdpFeatureType.ID_TO_FEATURE_MAP.keySet());
						}
					}

					if (!featureIDs.add(featureID))
					{
						throw new IllegalArgumentException("Duplicate feature: " + featureID);
					}

					// if feature not enabled, skip it since by default, all
					// features are disabled (request filter "disabled" means
					// here that it it is set to default value)
					if (!feature.isEnabled())
					{
						continue;
					}

					switch (nonNullFeatureType)
					{
						case CORE:
							final PdpCoreFeature coreFeature = PdpCoreFeature.fromId(featureID);
							if (coreFeature == null)
							{
								throw new IllegalArgumentException("Invalid " + nonNullFeatureType + " feature: '" + featureID + "'. Expected: " + PDP_FEATURE_IDENTIFIERS_BY_TYPE.get(nonNullFeatureType));
							}

							switch (coreFeature)
							{
								case XPATH_EVAL:
									enableXPath = true;
									break;
								case STRICT_ATTRIBUTE_ISSUER_MATCH:
									enableStrictAttIssuerMatch = true;
									break;
								default:
									throw new UnsupportedOperationException("Unsupported " + nonNullFeatureType + " feature: '" + featureID + "'. Expected: " + PDP_FEATURE_IDENTIFIERS_BY_TYPE.get(nonNullFeatureType));
							}

							break;

						case DATATYPE:
							newAttDatatypes.add(featureID);
							break;

						case FUNCTION:
							newPdpFunctions.add(featureID);
							break;

						case COMBINING_ALGORITHM:
							newCombiningAlgs.add(featureID);
							break;

						case REQUEST_PREPROC:
							/*
							 * Verify that this (extension) is supported. This throws IllegalArgumentException if not supported.
							 */
							final DecisionRequestPreprocessor.Factory<?, ?> reqPreprocFactory = PdpExtensions.getExtension(DecisionRequestPreprocessor.Factory.class, featureID);
							final Class<?> reqPreprocInType = reqPreprocFactory.getInputRequestType();
							final DecisionRequestPreprocessor.Factory<?, ?> conflictingReqPreprocFactory = reqPreprocFactoriesByInputType.put(reqPreprocInType, reqPreprocFactory);
							/*
							 * If there is a conflict with different preproc, this is invalid
							 */
							if (conflictingReqPreprocFactory != null && !conflictingReqPreprocFactory.getId().equals(featureID))
							{
								throw new IllegalArgumentException(
										"Feature conflict on '" + conflictingReqPreprocFactory.getId() + "' and '" + featureID + "'. These request preprocessors (feature type '"
												+ PdpFeatureType.REQUEST_PREPROC.id + "') have same input type (" + reqPreprocInType + "). Only one of them may be enabled at a time.");
							}

							/*
							 * We put an entry with null value to indicate a result postproc can be enabled for the given input type (= output type from request preproc) because there is an
							 * request-preproc enabled to produce it
							 */
							resultProcIdentifiersByInputType.put(reqPreprocFactory.getOutputRequestType(), null);
							break;

						case RESULT_POSTPROC:
							final DecisionResultPostprocessor.Factory<?, ?> resultPostprocFactory = PdpExtensions.getExtension(DecisionResultPostprocessor.Factory.class, featureID);
							final Class<?> resultPostprocInType = resultPostprocFactory.getRequestType();
							if (!resultProcIdentifiersByInputType.containsKey(resultPostprocInType))
							{
								throw new IllegalArgumentException("Cannot enable feature '" + featureID + "' (type " + PdpFeatureType.RESULT_POSTPROC.id
										+ ") because no compatible request preprocessor (feature type " + PdpFeatureType.REQUEST_PREPROC.id
										+ ") previously defined. Make sure you enable such a request-preproc feature (output must be " + resultPostprocInType + ") before this one.");
							}

							final String conflictingResultPostprocId = resultProcIdentifiersByInputType.put(resultPostprocInType, resultPostprocFactory.getId());
							if (conflictingResultPostprocId != null && !conflictingResultPostprocId.equals(featureID))
							{
								throw new IllegalArgumentException("Feature conflict on '" + conflictingResultPostprocId + "' and '" + featureID + "'. These result postprocessors (feature type '"
										+ PdpFeatureType.RESULT_POSTPROC.id + "') have same input type (" + resultPostprocInType + "). Only one of them may be enabled at a time.");
							}

							break;

						default:
							throw new UnsupportedOperationException("Unsupported PDP feature type: '" + nonNullFeatureType.id + "'. Expected: " + PdpFeatureType.ID_TO_FEATURE_MAP.keySet());
					}
				} // END COLLECT INPUT FEATURES

				for (final DecisionRequestPreprocessor.Factory<?, ?> reqPreprocFactory : reqPreprocFactoriesByInputType.values())
				{
					final String reqPreprocId = reqPreprocFactory.getId();
					/*
					 * Result proc may be null (if none defined, some default one is used)
					 */
					final String resultPreprocId = resultProcIdentifiersByInputType.get(reqPreprocFactory.getOutputRequestType());
					newIoProcChains.add(new InOutProcChain(reqPreprocId, resultPreprocId));
				}

				final TopLevelPolicyElementRef rootPolicyRef = new TopLevelPolicyElementRef(newRootPolicyRefExpression.getValue(), newRootPolicyRefExpression.getVersion(), true);

				final Pdp newPdpConf = new Pdp(newAttDatatypes, newPdpFunctions, newCombiningAlgs, pdpConf.getAttributeProviders(), pdpConf.getPolicyProviders(), rootPolicyRef, pdpConf.getDecisionCache(), newIoProcChains, pdpConf.getVersion(), pdpConf.isStandardDatatypesEnabled(), pdpConf.isStandardFunctionsEnabled(), pdpConf.isStandardCombiningAlgorithmsEnabled(), pdpConf.isStandardAttributeProvidersEnabled(), enableXPath, enableStrictAttIssuerMatch, pdpConf.getMaxIntegerValue(), pdpConf.getMaxVariableRefDepth(), pdpConf.getMaxPolicyRefDepth(), pdpConf.getClientRequestErrorVerbosityLevel());
				reloadPDP(newPdpConf);

				final List<PdpFeature> pdpFeatures = getPdpFeatures(newPdpConf);
				final List<TopLevelPolicyElementRef> activePolicyRefs = getPdpApplicablePolicyRefs();
				return new ReadablePdpPropertiesImpl(pdpFeatures, rootPolicyRef, activePolicyRefs.get(0), activePolicyRefs.subList(1, activePolicyRefs.size()), lastPdpSyncedTime);
			}
		}

		@Override
		public ReadablePdpProperties getOtherPdpProperties() throws IOException
		{
			if (enablePdpOnly)
			{
				throw DISABLED_OPERATION_EXCEPTION;
			}

			synchronized (domainDirPath)
			{
				final long lastModifiedTime = pdpConfFile.lastModified();
				final boolean isFileModified = lastModifiedTime > lastPdpSyncedTime;
				if (LOGGER.isDebugEnabled())
				{
					LOGGER.debug("Domain '{}': PDP conf file '{}': lastModifiedTime (= {}) {} last sync time (= {}){}", domainId, pdpConfFile,
							utcDateWithMillisFormatter.format(new Date(lastModifiedTime)), isFileModified ? ">" : "<=", utcDateWithMillisFormatter.format(new Date(lastPdpSyncedTime)),
							isFileModified ? " -> reload PDP" : "");
				}

				// let's sync
				final long pdpConfLastSyncedTime = System.currentTimeMillis();
				/*
				 * Get current PDP configuration that we have to change (only part of it)
				 */
				final Pdp pdpConf = loadPDPConfTmpl();

				if (isFileModified)
				{
					// then PDP's last sync time is same as last time PDP conf
					// was loaded/synced
					lastPdpSyncedTime = pdpConfLastSyncedTime;
					reloadPDP(pdpConf);
				} else
				{
					final boolean isPdpReloaded = syncPdpPolicies();
					// if reloaded, lastPdpSyncedTime is already set properly,
					// else we set it here
					if (!isPdpReloaded)
					{
						lastPdpSyncedTime = pdpConfLastSyncedTime;
					}
				}

				// Collect PDP features
				final List<PdpFeature> features = getPdpFeatures(pdpConf);
				final List<TopLevelPolicyElementRef> activePolicyRefs = getPdpApplicablePolicyRefs();
				return new ReadablePdpPropertiesImpl(features, pdpConf.getRootPolicyRef(), activePolicyRefs.get(0), activePolicyRefs.subList(1, activePolicyRefs.size()), lastPdpSyncedTime);
			}
		}

		@Override
		public List<AbstractAttributeProvider> setAttributeProviders(final List<AbstractAttributeProvider> attributeproviders) throws IOException, IllegalArgumentException
		{
			if (enablePdpOnly)
			{
				throw DISABLED_OPERATION_EXCEPTION;
			}

			if (attributeproviders == null)
			{
				throw NULL_ATTRIBUTE_PROVIDERS_ARGUMENT_EXCEPTION;
			}

			// Synchronize changes on PDP (and other domain conf data) from
			// multiple threads, keep minimal things in the synchronized block
			synchronized (domainDirPath)
			{
				lastPdpSyncedTime = System.currentTimeMillis();
				final Pdp pdpConf = loadPDPConfTmpl();
				final Pdp newPdpConf = new Pdp(pdpConf.getAttributeDatatypes(), pdpConf.getFunctions(), pdpConf.getCombiningAlgorithms(), attributeproviders, pdpConf.getPolicyProviders(), pdpConf.getRootPolicyRef(), pdpConf.getDecisionCache(), pdpConf.getIoProcChains(), pdpConf.getVersion(), pdpConf.isStandardDatatypesEnabled(), pdpConf.isStandardFunctionsEnabled(), pdpConf.isStandardCombiningAlgorithmsEnabled(), pdpConf.isStandardAttributeProvidersEnabled(), pdpConf.isXPathEnabled(), pdpConf.isStrictAttributeIssuerMatch(), pdpConf.getMaxIntegerValue(), pdpConf.getMaxVariableRefDepth(), pdpConf.getMaxPolicyRefDepth(), pdpConf.getClientRequestErrorVerbosityLevel());
				reloadPDP(newPdpConf);
			}

			return attributeproviders;
		}

		@Override
		public List<AbstractAttributeProvider> getAttributeProviders() throws IOException
		{
			if (enablePdpOnly)
			{
				throw DISABLED_OPERATION_EXCEPTION;
			}

			/*
			 * Synchronize changes on PDP (and other domain conf data) from multiple threads, keep minimal things in the synchronized block
			 */
			final Pdp pdpConf;
			synchronized (domainDirPath)
			{
				final long lastModifiedTime = pdpConfFile.lastModified();
				final boolean isFileModified = lastModifiedTime > lastPdpSyncedTime;
				if (LOGGER.isDebugEnabled())
				{
					LOGGER.debug("Domain '{}': PDP conf file '{}': lastModifiedTime (= {}) {} last sync time (= {}){}", domainId, pdpConfFile,
							utcDateWithMillisFormatter.format(new Date(lastModifiedTime)), isFileModified ? ">" : "<=", utcDateWithMillisFormatter.format(new Date(lastPdpSyncedTime)),
							isFileModified ? " -> reloading PDP" : "");
				}

				// let's sync
				final long pdpConfLastLoadTime = System.currentTimeMillis();
				pdpConf = loadPDPConfTmpl();
				if (isFileModified)
				{
					lastPdpSyncedTime = pdpConfLastLoadTime;
					reloadPDP(pdpConf);
				}
			}

			return pdpConf.getAttributeProviders();
		}

		/**
		 * Get policy-specific directory
		 *
		 * @param policyId policy ID
		 * @return policy directory (created or not, i.e. to be created)
		 */
		private Path getPolicyDirectory(final String policyId)
		{
			assert policyId != null;
			// Name of directory is base64url-encoded policyID (no padding)
			final String policyDirName = FlatFileDAOUtils.base64UrlEncode(policyId);
			return this.policyParentDirPath.resolve(policyDirName);
		}

		/**
		 * Save/write policy to file
		 *
		 * @param path target file path
		 * @throws IOException I/O error accessing path
		 */
		private void savePolicy(final PolicySet policy, final Path path, Map<String, String> xpathNamespaceContexts) throws IOException
		{
			assert policy != null;
			assert path != null;

			/*
			 * Parent directory is used as container for all versions of the PolicySet (same PolicySetid)
			 */
			final Path policyDir = path.getParent();
			if (policyDir == null)
			{
				/*
				 * This should never happen
				 */
				throw new RuntimeException("savePolicy(..., path) called with path having no parent! Root path?");
			}

			try
			{
				Files.createDirectories(policyDir);
			} catch (final IOException e)
			{
				throw new IOException("Error creating parent directory for new policy ('" + policy.getPolicySetId() + "' v" + policy.getVersion() + ") in domain '" + domainId + "'", e);
			}

			XMLStreamWriter xmlStreamWriter = null;
			try (FileWriter fileWriter = new FileWriter(path.toFile(), StandardCharsets.UTF_8))
			{
				xmlStreamWriter = StaxUtils.createXMLStreamWriter(fileWriter);
				/*
				Add back the XPath namespace contexts if any as namespace declaration (xmlns:prefix="uri")
				 */
				final Marshaller marshaller = Xacml3JaxbHelper.createXacml3Marshaller();
				marshaller.marshal(policy, xpathNamespaceContexts.isEmpty() ? xmlStreamWriter : new XmlnsAppendingDelegatingXMLStreamWriter(xmlStreamWriter, ImmutableMap.copyOf(xpathNamespaceContexts)));
				xmlStreamWriter.close();
			} catch (final JAXBException| XMLStreamException e)
			{
				throw new IOException("Error saving policy in domain '" + domainId + "'", e);
			} finally
			{
				StaxUtils.close(xmlStreamWriter);
			}
		}

		private Path getPolicyVersionPath(final Path policyDirPath, final PolicyVersion version)
		{
			return policyDirPath.resolve(version + this.policyFilePathFilter.getMatchedSuffix());
		}

		@Override
		public AuthzPolicy addPolicy(final AuthzPolicy policy) throws IOException, IllegalArgumentException, TooManyPoliciesException
		{
			if (enablePdpOnly)
			{
				throw DISABLED_OPERATION_EXCEPTION;
			}

			if (policy == null)
			{
				throw NULL_POLICY_ARGUMENT_EXCEPTION;
			}

			/*
			 * Before doing any further changes, we need to be sure we'll be able to sync/reload the PDP if this affects PDP's applicable policies, so make sure it is not in error state
			 */
			if (pdp == null || pdp.engine == null)
			{
				throw PDP_IN_ERROR_STATE_RUNTIME_EXCEPTION;
			}

			final PolicySet policySet = policy.toXacml();
			final String policyId = policySet.getPolicySetId();
			final Path policyDirPath = getPolicyDirectory(policyId);
			final PolicyVersion newPolicyVersion = new PolicyVersion(policySet.getVersion());
			final Path policyVersionFile = getPolicyVersionPath(policyDirPath, newPolicyVersion);

			synchronized (domainDirPath)
			{
				if (Files.exists(policyVersionFile, LinkOption.NOFOLLOW_LINKS))
				{
					/*
					 * conflict: same policy version already exists, return it
					 */
					// make sure the PDP is in sync with the returned policy
					// version
					syncPDP();
					try
					{
						return FlatFileDAOUtils.loadPolicy(policyVersionFile);
					} catch (final JAXBException e)
					{
						throw new IOException("Error getting a policy of domain '" + domainId + "'", e);
					}
				}

				/*
				 * Policy version file does not exist, but does the policy has any version already, i.e. does a directory exist for the policy?
				 */
				final DomainProperties domainProps = loadProperties();

				if (!Files.exists(policyDirPath))
				{
					/*
					 * No such directory -> new policy (and new version a fortiori), check whether the number of policies has reached the limit
					 */
					final BigInteger maxPolicyCount = domainProps.getMaxPolicyCount();
					if (maxPolicyCount != null)
					{
						int existingPolicyCount = 0;
						try (DirectoryStream<Path> policyParentDirStream = Files.newDirectoryStream(policyParentDirPath, FlatFileDAOUtils.SUB_DIRECTORY_STREAM_FILTER))
						{
							for (final Iterator<Path> fileIt = policyParentDirStream.iterator(); fileIt.hasNext(); fileIt.next())
							{
								existingPolicyCount++;
							}
						} catch (final IOException e)
						{
							throw new IOException("Error listing files in policies directory '" + policyParentDirPath + "' of domain '" + domainId + "'", e);
						}

						if (existingPolicyCount >= maxPolicyCount.intValue())
						{
							/*
							 * We already reached or exceeded the max, so if we add one more as we are about to do, we have too many anyway (existingPolicyCount > maxNumOfPoliciesPerDomain)
							 */
							throw new TooManyPoliciesException("Max number of policies (" + maxPolicyCount + ") reached for the domain");
						}
					}

					/*
					 * WARNING: at this point, we don't change anything on the filesystem - so we don't yet create the policy directory - until the input PolicySet is fully validated with the current
					 * PDP configuration (for semantic checking in particular). The policy directory may be created later when the savePolicy() is finally called.
					 */
				}

				final BigInteger maxVersionCountPerPolicy = domainProps.getMaxVersionCountPerPolicy();
				final TooManyPoliciesException maxNumOfVersionsReachedException = new TooManyPoliciesException(
						"Max number of versions (" + maxVersionCountPerPolicy + ") reached for the policy and none can be removed");
				final PolicyVersions<Path> policyVersions = getPolicyVersions(policyDirPath);
				final int excessOfPolicyVersionsToBeRemoved;

				/*
				 * New policy version. Check whether number of versions >= max
				 */
				if (maxVersionCountPerPolicy != null)
				{
					/*
					 * Number of policies to remove in case auto removal of excess versions is enabled is: number of current versions + the new one to be added - max
					 */
					excessOfPolicyVersionsToBeRemoved = policyVersions.size() + 1 - maxVersionCountPerPolicy.intValue();
					/*
					 * if excessOfPolicyVersionsToBeRemoved > 0, we cannot add one more (that would cause policyVersions.size() > maxNumOfVersionsPerPolicy). In this case, if
					 * removeOldestVersionsIfMaxExceeded property is false, we cannot remove any version to allow for the new one -> throw an error
					 */
					if (excessOfPolicyVersionsToBeRemoved > 0 && !domainProps.isVersionRollingEnabled())
					{
						/*
						 * Oldest versions will not be removed, therefore we cannot add policies anymore without exceeding max
						 */
						throw maxNumOfVersionsReachedException;
					}
				} else
				{
					// number of versions per policy is unlimited
					excessOfPolicyVersionsToBeRemoved = 0;
				}

				/*
				 * Last input validation before we can save/persist the policy on the filesystem: verify that the new policy is semantically valid (e.g. identifiers, references, etc.) and supported by
				 * the current PDP configuration: data-types, functions, etc. To do that:
				 *
				 * 1) Get current (up-to-date) PDP configuration.
				 *
				 * 2) Load the input policy as if it was the PDP's root policy. Indeed, any input policy must be supported as possible root policy for the PDP.
				 */
				/*
				 * Step 1)
				 */
				syncPDP();
				final Pdp pdpConfTmpl = loadPDPConfTmpl();
				/*
				 * Step 2) Let's change the PDP configuration to: a) add a policy provider with the new policy; b) set the new policy as root
				 */
				final List<AbstractPolicyProvider> newPolicyProviders = new ArrayList<>(pdpConfTmpl.getPolicyProviders());
				newPolicyProviders.add(new StaticPolicyProvider(Collections.singletonList(policySet), true));
				final TopLevelPolicyElementRef newRootPolicyRef = new TopLevelPolicyElementRef(policyId, policySet.getVersion(), true);
				final Pdp newPdpConf = new Pdp(pdpConfTmpl.getAttributeDatatypes(), pdpConfTmpl.getFunctions(), pdpConfTmpl.getCombiningAlgorithms(), pdpConfTmpl.getAttributeProviders(), newPolicyProviders, newRootPolicyRef, pdpConfTmpl.getDecisionCache(), pdpConfTmpl.getIoProcChains(), pdpConfTmpl.getVersion(), pdpConfTmpl.isStandardDatatypesEnabled(), pdpConfTmpl.isStandardFunctionsEnabled(), pdpConfTmpl.isStandardCombiningAlgorithmsEnabled(), pdpConfTmpl.isStandardAttributeProvidersEnabled(), pdpConfTmpl.isXPathEnabled(), pdpConfTmpl.isStrictAttributeIssuerMatch(), pdpConfTmpl.getMaxIntegerValue(), pdpConfTmpl.getMaxVariableRefDepth(), pdpConfTmpl.getMaxPolicyRefDepth(), pdpConfTmpl.getClientRequestErrorVerbosityLevel());

				/*
				 * Root policy ref modified in PDP config. Let's try to load the new config to validate.
				 */

				final Map<String, String> xpathNamespaceContexts = policy.getXPathNamespaceContexts();
				final PdpEngineConfiguration pdpEngineConf = new PdpEngineConfiguration(newPdpConf, pdpConfEnvProps, xpathNamespaceContexts);
				try (CloseablePdpEngine tempPdp = new BasePdpEngine(pdpEngineConf))
				{
					LOGGER.debug("New policy '{}' v{} validated (successfully loaded a temporary PDP with this policy as root: {})", policyId, newPolicyVersion, tempPdp);
				}

				/*
				 * The new policy may be saved now as considered valid (no exception raised so far).
				 */
				savePolicy(policySet, policyVersionFile, xpathNamespaceContexts);

				/*
				 * Do the PDP reload if and only if the new policy is likely to be applicable (match a direct/indirect policy reference from root policy), i.e. if a policy with same ID is already
				 * applicable but with an earlier version than the input one, so the input one may replace it. We already called syncPDP() so we have the latest view of applicable policies.
				 */
				final Optional<PrimaryPolicyMetadata> matchingRequiredPolicySetMetadata = StreamSupport.stream(pdp.engine.getApplicablePolicies().spliterator(), false)
						.filter(policyMeta -> policyMeta.getType() == TopLevelPolicyElementType.POLICY_SET && policyMeta.getId().equals(policyId)).findFirst();
				final PolicyVersion currentlyUsedPolicyVersion = matchingRequiredPolicySetMetadata.map(PrimaryPolicyMetadata::getVersion).orElse(null);
				if (currentlyUsedPolicyVersion != null && currentlyUsedPolicyVersion.compareTo(newPolicyVersion) < 0)
				{
					/*
					 * new policy version may be applicable instead of requiredPolicyVersion (because policy with same ID already applicable but earlier than the new one, and we know the PDP's policy
					 * finder takes the latest possible applicable policy version)
					 */
					try
					{
						reloadPDP();
					} catch (final Throwable e)
					{
						/*
						 * PDP reload failed -> rollback: remove the policy version
						 */
						removePolicyVersionFile(policyVersionFile, e);
						throw e;
					}
				}

				/*
				 * Make sure that if there are too many versions (including the new one), we can actually remove enough old versions to make place for the new one. First
				 */
				if (excessOfPolicyVersionsToBeRemoved > 0)
				{
					/*
					 * too many versions, we need to remove some (the oldest that are not required by the PDP)
					 */
					final Iterator<Entry<PolicyVersion, Path>> oldestToLatestVersionIterator = policyVersions.oldestToLatestIterator();
					int numRemoved = 0;
					while (oldestToLatestVersionIterator.hasNext() && numRemoved < excessOfPolicyVersionsToBeRemoved)
					{
						final Entry<PolicyVersion, Path> versionWithPath = oldestToLatestVersionIterator.next();
						/*
						 * remove only if not required (requiredPolicyVersion may be null, i.e. no required version, equals returns false in this case)
						 */
						final PolicyVersion version = versionWithPath.getKey();
						if (version.equals(currentlyUsedPolicyVersion))
						{
							continue;
						}

						removePolicyVersionFile(versionWithPath.getValue(), null);
						if (version.equals(newPolicyVersion))
						{
							/*
							 * the version we tried to add is removed, so overall, the addPolicy() failed, therefore throw an exception
							 */
							throw maxNumOfVersionsReachedException;
						}

						numRemoved++;
					}

					if (numRemoved < excessOfPolicyVersionsToBeRemoved)
					{
						/*
						 * This should not happen, but if we could not remove enough, no more place for the new one, this is an error
						 */
						throw maxNumOfVersionsReachedException;
					}

				}

				// PDP reloaded successfully
			}

			return null;
		}

		private Path getPolicyVersionPath(final String policyId, final PolicyVersion versionId)
		{
			return getPolicyDirectory(policyId).resolve(versionId + this.policyFilePathFilter.getMatchedSuffix());
		}

		@Override
		public AuthzPolicy getPolicyVersion(final String policyId, final PolicyVersion version) throws IOException
		{
			if (enablePdpOnly)
			{
				throw DISABLED_OPERATION_EXCEPTION;
			}

			if (policyId == null || version == null)
			{
				return null;
			}
			/*
			 * Make sure the PDP is in sync with the returned policy version
			 */
			synchronized (domainDirPath)
			{
				syncPDP();
				final Path policyVersionFile = getPolicyVersionPath(policyId, version);
				if (!Files.exists(policyVersionFile, LinkOption.NOFOLLOW_LINKS))
				{
					// no such policy version
					return null;
				}

				try
				{
					return FlatFileDAOUtils.loadPolicy(policyVersionFile);
				} catch (IllegalArgumentException | JAXBException e)
				{
					throw new IOException("Error getting policy version from file '" + policyVersionFile + "'", e);
				}
			}
		}

		private void removePolicyVersionFile(final Path policyVersionFilepath, final Throwable causeForRemoving) throws IOException
		{
			try
			{
				Files.deleteIfExists(policyVersionFilepath);

				/*
				 * Check whether the policy directory is left empty (no more version)
				 */
				final Path policyDirPath = policyVersionFilepath.getParent();
				if (policyDirPath == null || !Files.exists(policyDirPath, LinkOption.NOFOLLOW_LINKS))
				{
					return;
				}

				try (DirectoryStream<Path> policyDirStream = Files.newDirectoryStream(policyDirPath, policyFilePathFilter))
				{
					if (!policyDirStream.iterator().hasNext())
					{
						// policy directory left empty of versions -> remove
						// it
						FlatFileDAOUtils.deleteDirectory(policyDirPath, 1);
					}
				} catch (final IOException e)
				{
					throw new IOException("Error checking if policy directory '" + policyDirPath + "' is empty or removing it after removing last version"
							+ (causeForRemoving == null ? "" : " causing PDP instantiation failure: " + causeForRemoving) + ". Please delete the directory manually and reload the domain.", e);
				}

			} catch (final IOException e)
			{

				throw new IOException("Failed to delete policy file: '" + policyVersionFilepath + "'" + (causeForRemoving == null ? "" : " causing PDP instantiation failure: " + e.getMessage()), e);
			}
		}

		@Override
		public AuthzPolicy removePolicyVersion(final String policyId, final PolicyVersion tobeRemovedPolicyVersion) throws IOException, IllegalArgumentException
		{
			if (enablePdpOnly)
			{
				throw DISABLED_OPERATION_EXCEPTION;
			}

			if (policyId == null || tobeRemovedPolicyVersion == null)
			{
				return null;
			}

			/*
			 * Before doing any further changes, we need to be sure we'll be able to sync/reload the PDP if this affects PDP's applicable policies, so make sure it is not in error state
			 */
			if (pdp == null || pdp.engine == null)
			{
				throw PDP_IN_ERROR_STATE_RUNTIME_EXCEPTION;
			}

			final Path policyVersionFile = getPolicyVersionPath(policyId, tobeRemovedPolicyVersion);
			final AuthzPolicy policy;
			synchronized (domainDirPath)
			{
				/*
				 * Check whether it is not used by the PDP. First make sure the PDP is up-to-date with the repository
				 */
				syncPDP();
				final Optional<PrimaryPolicyMetadata> matchingRequiredPolicySetMetadata = StreamSupport.stream(pdp.engine.getApplicablePolicies().spliterator(), false)
						.filter(policyMeta -> policyMeta.getType() == TopLevelPolicyElementType.POLICY_SET && policyMeta.getId().equals(policyId)).findFirst();
				final PolicyVersion currentlyUsedVersion = matchingRequiredPolicySetMetadata.map(PrimaryPolicyMetadata::getVersion).orElse(null);
				if (tobeRemovedPolicyVersion.equals(currentlyUsedVersion))
				{
					throw new IllegalArgumentException("Policy '" + policyId + "' / Version " + tobeRemovedPolicyVersion
							+ " cannot be removed because it is still used by the PDP, either as root policy or referenced directly/indirectly by the root policy.");
				}

				if (!Files.exists(policyVersionFile, LinkOption.NOFOLLOW_LINKS))
				{
					// already absent
					return null;
				}

				try
				{
					policy = FlatFileDAOUtils.loadPolicy(policyVersionFile);
				} catch (final JAXBException e)
				{
					throw new IOException("Error getting policy version from file '" + policyVersionFile + "'", e);
				}

				removePolicyVersionFile(policyVersionFile, null);

			}

			return policy;
		}

		@Override
		public VERSION_DAO_CLIENT getVersionDaoClient(final String policyId, final PolicyVersion version)
		{
			/*
			 * policyVersionDaoClientFactory == null iff enablePdpOnly (see constructor)
			 */
			if (policyVersionDaoClientFactory == null)
			{
				throw DISABLED_OPERATION_EXCEPTION;
			}

			if (policyId == null || version == null)
			{
				return null;
			}

			return policyVersionDaoClientFactory.getInstance(policyId, version, this);
		}

		@Override
		public PolicyVersion getLatestPolicyVersionId(final String policyId) throws IOException
		{
			if (enablePdpOnly)
			{
				throw DISABLED_OPERATION_EXCEPTION;
			}

			if (policyId == null)
			{
				return null;
			}

			/*
			 * We could cache this, but this is meant to be used as a DAO in a REST API, i.e. the API should be stateless as much as possible. Therefore, we should avoid caching when performance is
			 * not critical (the performance-critical part is getPDP() only). Also this should be in sync as much as possible with the filesystem.
			 */
			/*
			 * Make sure the PDP is in sync/consistent with the info returned (last version)
			 */
			final Entry<PolicyVersion, Path> latestVersionAndFilepath;
			synchronized (domainDirPath)
			{
				final Path policyDirPath = getPolicyDirectory(policyId);
				if (!Files.exists(policyDirPath) || !Files.isDirectory(policyDirPath))
				{
					return null;
				}

				try
				{
					latestVersionAndFilepath = FlatFileDAOUtils.getLatestPolicyVersion(policyDirPath, policyFilePathFilter);
				} catch (final IOException e)
				{
					throw new IOException("Error listing policy version files in policy directory '" + policyDirPath + "' of domain '" + domainId + "'", e);
				}

				// Sync the PDP with info returned
				syncPDP();
			}

			return latestVersionAndFilepath.getKey();
		}

		/**
		 * Get policy versions from policy directory, ordered from latest to oldest
		 *
		 * @param policyDirPath path to policy directory
		 * @return versions; empty if directory does not exist or is not a directory
		 * @throws IOException I/O error accessing policy directory
		 */
		private PolicyVersions<Path> getPolicyVersions(final Path policyDirPath) throws IOException
		{
			assert policyDirPath != null;

			if (!Files.exists(policyDirPath) || !Files.isDirectory(policyDirPath))
			{
				return EMPTY_POLICY_VERSIONS;
			}

			try
			{
				return FlatFileDAOUtils.getPolicyVersions(policyDirPath, this.policyFilePathFilter);
			} catch (final IOException e)
			{
				throw new IOException("Error listing policy version files in policy directory '" + policyDirPath + "' of domain '" + domainId + "'", e);
			}
		}

		/**
		 * Get number of policy versions from policy directory
		 *
		 * @param policyDirPath path to policy directory
		 * @return number of versions; 0 if directory does not exist or is not a directory
		 * @throws IOException I/O error accessing policy directory
		 */
		private int getPolicyVersionCount(final Path policyDirPath) throws IOException
		{
			assert policyDirPath != null;

			if (!Files.exists(policyDirPath) || !Files.isDirectory(policyDirPath))
			{
				return 0;
			}

			int count = 0;
			try (DirectoryStream<Path> policyDirStream = Files.newDirectoryStream(policyDirPath, policyFilePathFilter))
			{
				for (final Iterator<Path> fileIt = policyDirStream.iterator(); fileIt.hasNext(); fileIt.next())
				{
					count++;
				}

			} catch (final IOException e)
			{
				throw new IOException("Error listing policy version files in policy directory '" + policyDirPath + "' of domain '" + domainId + "'", e);
			}

			return count;
		}

		@Override
		public NavigableSet<PolicyVersion> getPolicyVersions(final String policyId) throws IOException
		{
			if (enablePdpOnly)
			{
				throw DISABLED_OPERATION_EXCEPTION;
			}

			if (policyId == null)
			{
				return ImmutableSortedSet.of();
			}

			final NavigableSet<PolicyVersion> versions;
			/*
			 * We could cache this, but this is meant to be used as a DAO in a REST API, i.e. the API should be stateless as much as possible. Therefore, we should avoid caching when performance is
			 * not critical (the performance-critical part is getPDP() only). Also this should be in sync as much as possible with the filesystem.
			 */
			synchronized (domainDirPath)
			{
				final Path policyDir = getPolicyDirectory(policyId);
				versions = getPolicyVersions(policyDir).latestToOldestSet();
				// make sure the current PDP state is consistent with the info
				// returned
				syncPDP();
			}

			return versions;
		}

		@Override
		public POLICY_DAO_CLIENT getPolicyDaoClient(final String policyId)
		{
			/*
			 * policyDaoClientFactory == null iff enablePdpOnly (see constructor)
			 */
			if (policyDaoClientFactory == null)
			{
				throw DISABLED_OPERATION_EXCEPTION;
			}

			if (policyId == null)
			{
				return null;
			}

			return policyDaoClientFactory.getInstance(policyId, this);
		}

		@Override
		public NavigableSet<PolicyVersion> removePolicy(final String policyId) throws IOException, IllegalArgumentException
		{
			if (enablePdpOnly)
			{
				throw DISABLED_OPERATION_EXCEPTION;
			}

			if (policyId == null)
			{
				return ImmutableSortedSet.of();
			}

			/*
			 * Before doing any further changes, we need to be sure we'll be able to sync/reload the PDP if this affects PDP's applicable policies, so make sure it is not in error state
			 */
			if (pdp == null || pdp.engine == null)
			{
				throw PDP_IN_ERROR_STATE_RUNTIME_EXCEPTION;
			}

			final PolicyVersion currentlyUsedVersion;
			final NavigableSet<PolicyVersion> versions;
			synchronized (domainDirPath)
			{
				syncPDP();
				final Optional<PrimaryPolicyMetadata> matchingRequiredPolicySetMetadata = StreamSupport.stream(pdp.engine.getApplicablePolicies().spliterator(), false)
						.filter(policyMeta -> policyMeta.getType() == TopLevelPolicyElementType.POLICY_SET && policyMeta.getId().equals(policyId)).findFirst();
				currentlyUsedVersion = matchingRequiredPolicySetMetadata.map(PrimaryPolicyMetadata::getVersion).orElse(null);
				if (currentlyUsedVersion != null)
				{
					throw new IllegalArgumentException("Policy '" + policyId + "' cannot be removed because this policy (version " + currentlyUsedVersion
							+ ") is still used by the PDP, either as root policy or referenced directly/indirectly by the root policy.");
				}

				final Path policyDir = getPolicyDirectory(policyId);
				versions = getPolicyVersions(policyDir).latestToOldestSet();
				try
				{
					// if directory does not exist, this method just returns
					// right away
					FlatFileDAOUtils.deleteDirectory(policyDir, 1);
				} catch (final IOException e)
				{
					throw new IOException("Error removing policy directory: " + policyDir, e);
				}
			}

			return versions;
		}

		/**
		 * Must be called withing synchronized (domainDirPath) block
		 *
		 * @return number of policies in the policy repository (policies directory)
		 * @throws IOException I/O error accessing th policies (parent) directory
		 */
		private int getPolicyCount() throws IOException
		{
			/*
			 * We could cache this, but this is meant to be used as a DAO in a REST API, i.e. the API should be as stateless as possible. Therefore, we should avoid caching when performance is not
			 * critical (the performance-critical part is getPDP() only). Also this should be in sync as much as possible with the filesystem.
			 */
			int count = 0;
			try (DirectoryStream<Path> policyParentDirStream = Files.newDirectoryStream(policyParentDirPath, FlatFileDAOUtils.SUB_DIRECTORY_STREAM_FILTER))
			{
				for (final Iterator<Path> fileIt = policyParentDirStream.iterator(); fileIt.hasNext(); fileIt.next())
				{
					count++;
				}
			} catch (final IOException e)
			{
				throw new IOException("Error listing files in policies directory '" + policyParentDirPath + "' of domain '" + domainId + "'", e);
			}

			return count;
		}

		/**
		 * Must be called within synchronized (domainDirPath) block
		 *
		 * @return an example of current (p, v), such as p is a policy with a number of versions v > {@code maxAllowedVersionCount}; or null if all policies are OK (number of versions is lower or
		 * equal).
		 * @throws IOException I/O error accessing policies (parent) directory
		 */
		private Entry<String, Integer> checkPolicyVersionCount(final int maxAllowedVersionCount) throws IOException
		{
			if (maxAllowedVersionCount < 1)
			{
				// value 0 or negative considered as unlimited
				return null;
			}

			/*
			 * We could cache this, but this is meant to be used as a DAO in a REST API, i.e. the API should be as stateless as possible. Therefore, we should avoid caching when performance is not
			 * critical (the performance-critical part is getPDP() only). Also this should be in sync as much as possible with the filesystem.
			 */
			try (DirectoryStream<Path> policyParentDirStream = Files.newDirectoryStream(policyParentDirPath, FlatFileDAOUtils.SUB_DIRECTORY_STREAM_FILTER))
			{
				for (final Path policyDirPath : policyParentDirStream)
				{
					final int versionCount = getPolicyVersionCount(policyDirPath);
					if (versionCount > maxAllowedVersionCount)
					{
						final Path policyDirName = policyDirPath.getFileName();
						if (policyDirName == null)
						{
							throw new IOException("Invalid policy (versions) directory path: " + policyDirPath);
						}

						final String encodedPolicyId = policyDirName.toString();
						final String policyId;
						try
						{
							policyId = FlatFileDAOUtils.base64UrlDecode(encodedPolicyId);
						} catch (final IllegalArgumentException e)
						{
							throw new RuntimeException("Invalid policy directory name (bad encoding): " + policyDirName, e);
						}

						return new SimpleImmutableEntry<>(policyId, versionCount);
					}
				}
			} catch (final IOException e)
			{
				throw new IOException("Error listing files in policies directory '" + policyParentDirPath + "' of domain '" + domainId + "'", e);
			}

			return null;
		}

		@Override
		public Set<String> getPolicyIdentifiers() throws IOException
		{
			if (enablePdpOnly)
			{
				throw DISABLED_OPERATION_EXCEPTION;
			}

			/*
			 * We could cache this, but this is meant to be used as a DAO in a REST API, i.e. the API should be as stateless as possible. Therefore, we should avoid caching when performance is not
			 * critical (the performance-critical part is getPDP() only). Also this should be in sync as much as possible with the filesystem.
			 */
			final Set<String> policyIds = new TreeSet<>();
			synchronized (domainDirPath)
			{
				try (DirectoryStream<Path> policyParentDirStream = Files.newDirectoryStream(policyParentDirPath, FlatFileDAOUtils.SUB_DIRECTORY_STREAM_FILTER))
				{
					for (final Path policyDirPath : policyParentDirStream)
					{
						final Path policyDirName = policyDirPath.getFileName();
						if (policyDirName == null)
						{
							throw new IOException("Invalid policy (versions) directory path: " + policyDirPath);
						}

						final String encodedPolicyId = policyDirName.toString();
						final String policyId;
						try
						{
							policyId = FlatFileDAOUtils.base64UrlDecode(encodedPolicyId);
						} catch (final IllegalArgumentException e)
						{
							throw new RuntimeException("Invalid policy directory name (bad encoding): " + policyDirName, e);
						}

						policyIds.add(policyId);
					}
				} catch (final IOException e)
				{
					throw new IOException("Error listing files in policies directory '" + policyParentDirPath + "' of domain '" + domainId + "'", e);
				}

				// make sure PDP is consistent/in sync with the info returned
				syncPDP();
			}

			return policyIds;
		}

		@Override
		public ReadableDomainProperties removeDomain() throws IOException
		{
			if (enablePdpOnly)
			{
				throw DISABLED_OPERATION_EXCEPTION;
			}

			synchronized (domainDirPath)
			{
				if (Files.exists(domainDirPath, LinkOption.NOFOLLOW_LINKS))
				{
					FlatFileDAOUtils.deleteDirectory(domainDirPath, 3);
				}

				synchronized (domainsRootDir)
				{
					removeDomainFromCache(domainId);
				}
			}

			return new ReadableDomainPropertiesImpl(domainId, null, cachedExternalId);
		}

		@Override
		public void close() throws IOException
		{
			// if synchronization enabled
			if (dirToMemSyncScheduler != null)
			{
				/*
				 * Code adapted from ExecutorService javadoc
				 */
				this.dirToMemSyncScheduler.shutdown(); // Disable new tasks from
				// being submitted
				try
				{
					// Wait a while for existing tasks to terminate
					if (!dirToMemSyncScheduler.awaitTermination(SYNC_SERVICE_SHUTDOWN_TIMEOUT_SEC, TimeUnit.SECONDS))
					{
						LOGGER.error("Domain '{}': scheduler wait timeout ({}s) occurred before task could terminate after shutdown request.", domainId, domainDirToMemSyncIntervalSec);
						dirToMemSyncScheduler.shutdownNow(); // Cancel currently
						// executing
						// tasks
						// Wait a while for tasks to respond to being cancelled
						if (!dirToMemSyncScheduler.awaitTermination(SYNC_SERVICE_SHUTDOWN_TIMEOUT_SEC, TimeUnit.SECONDS))
						{
							LOGGER.error("Domain '{}': scheduler wait timeout ({}s) occurred before task could terminate after shudownNow request.", domainId, domainDirToMemSyncIntervalSec);
						}
					}
				} catch (final InterruptedException ie)
				{
					LOGGER.error("Domain '{}': scheduler interrupted while waiting for sync task to complete", domainId, ie);
					// (Re-)Cancel if current thread also interrupted
					dirToMemSyncScheduler.shutdownNow();
					// Preserve interrupt status
					Thread.currentThread().interrupt();
				}
			}

			if (pdp != null && pdp.engine != null)
			{
				pdp.engine.close();
			}
		}

		@Override
		public PrpRwProperties getOtherPrpProperties() throws IOException
		{
			if (enablePdpOnly)
			{
				throw DISABLED_OPERATION_EXCEPTION;
			}

			final DomainProperties props;
			synchronized (domainsRootDir)
			{
				props = syncDomainProperties(false);
			}

			final BigInteger maxPolicyCount = props.getMaxPolicyCount();
			final BigInteger maxVersionCount = props.getMaxVersionCountPerPolicy();
			final int mpc = maxPolicyCount == null ? -1 : maxPolicyCount.intValue();
			final int mvc = maxVersionCount == null ? -1 : maxVersionCount.intValue();
			return new PrpRwPropertiesImpl(mpc, mvc, props.isVersionRollingEnabled());
		}

		@Override
		public PrpRwProperties setOtherPrpProperties(final PrpRwProperties props) throws IOException, IllegalArgumentException
		{
			if (enablePdpOnly)
			{
				throw DISABLED_OPERATION_EXCEPTION;
			}

			if (props == null)
			{
				throw NULL_PRP_PROPERTIES_ARGUMENT_EXCEPTION;
			}

			final DomainProperties updatedProps;
			synchronized (domainsRootDir)
			{
				updatedProps = loadProperties();
				final int maxPolicyCount = props.getMaxPolicyCountPerDomain();
				// check that new maxPolicyCount >= current policy count
				final int policyCount = getPolicyCount();
				// maxPolicyCount <= 0 considered unlimited
				if (maxPolicyCount > 0 && maxPolicyCount < policyCount)
				{
					throw new IllegalArgumentException("Invalid maxPolicyCount (" + maxPolicyCount + "): < current policy count (" + policyCount + ")!");
				}

				updatedProps.setMaxPolicyCount(maxPolicyCount > 0 ? BigInteger.valueOf(maxPolicyCount) : null);

				final int maxAllowedVersionCountPerPolicy = props.getMaxVersionCountPerPolicy();
				// check that new maxAllowedVersionCount >= version count of any
				// policy
				final Entry<String, Integer> invalidPolicyVersion = checkPolicyVersionCount(maxAllowedVersionCountPerPolicy);
				if (invalidPolicyVersion != null)
				{
					throw new IllegalArgumentException("Invalid maxVersionCount (" + maxAllowedVersionCountPerPolicy + "): < number of versions (" + invalidPolicyVersion.getValue() + ") of policy "
							+ invalidPolicyVersion.getKey() + "!");
				}

				updatedProps.setMaxVersionCountPerPolicy(maxAllowedVersionCountPerPolicy > 0 ? BigInteger.valueOf(maxAllowedVersionCountPerPolicy) : null);
				updatedProps.setVersionRollingEnabled(props.isVersionRollingEnabled());
				// validate and save new properties to disk
				saveProperties(updatedProps);
				syncDomainProperties(true);
			}

			return new PrpRwPropertiesImpl(props.getMaxPolicyCountPerDomain(), props.getMaxVersionCountPerPolicy(), props.isVersionRollingEnabled());
		}

		@Override
		public boolean isXacmlXmlSupported()
		{
			return pdp.isXacmlXmlSupportEnabled();
		}

		@Override
		public boolean isXacmlJsonSupported()
		{
			return pdp.isXacmlJsonSupportEnabled();
		}

		@Override
		public Response evaluatePolicyDecision(final Request request) throws UnsupportedOperationException
		{
			if (pdp == null)
			{
				throw NULL_PDP_ERROR;
			}

			return pdp.evaluate(request);
		}

		@Override
		public JSONObject evaluatePolicyDecision(final JSONObject request) throws UnsupportedOperationException
		{
			if (pdp == null)
			{
				throw NULL_PDP_ERROR;
			}

			return pdp.evaluate(request);
		}

	}

	/**
	 * Create domain DAO and register it in the map (incl. domainIDsByExternalId if props != null && props.getExternalId() != null). Must be called with {@code synchronized(domainsRootDir)} block
	 * 
	 * @param domainId domain ID
	 * @param domainDirectory domain directory
	 * @param props domain properties
	 *            (optional) specific domain properties, or null if default or no properties should be used
	 * @return the existing domain if a domain with such ID already exists in the map and properties unchanged ({@code props == null}), else the new domain
	 * @throws IOException I/O error accessing domainDirectory
	 * @throws IllegalArgumentException
	 *             if a domain with such ID already exists and {@code props != null}; OR there is an externalId conflict, i.e. the externalId is set in {@code props} but is already associated with
	 *             another domain (conflict)
	 */
	private synchronized DOMAIN_DAO_CLIENT addDomainToCacheAfterDirectoryCreated(final String domainId, final Path domainDirectory, final WritableDomainProperties props)
	        throws IOException, IllegalArgumentException
	{
		/*
		 * Assumed synchronized on domainsRootDir by the caller
		 */
		final DOMAIN_DAO_CLIENT prevDomain = this.domainMap.get(domainId);
		if (prevDomain != null)
		{
			if (props != null)
			{
				/*
				 * Domain already exists (domainId conflict)
				 */
				throw new IllegalArgumentException("Domain '" + domainId + "' already exists with possibly different properties than the ones in arguments");
			}
			// props == null
			return prevDomain;
		}
		// prevDomain == null
		final DOMAIN_DAO_CLIENT domainDaoClient = domainDaoClientFactory.getInstance(domainId, () -> {
			final FileBasedDomainDaoImpl domainDao = new FileBasedDomainDaoImpl(domainDirectory, props);
			if (props != null)
			{

				// IllegalArgumentException raised if externalId conflict
				domainDao.updateCachedExternalId(props.getExternalId());
			}

			return domainDao;
		});

		this.domainMap.put(domainId, domainDaoClient);

		return domainDaoClient;
	}

	/**
	 * Creates instance
	 * 
	 * @param domainsRoot
	 *            root directory of the configuration data of security domains, one subdirectory per domain
	 * @param domainTmpl
	 *            domain template directory; directories of new domains are created from this template
	 * @param domainsSyncIntervalSec
	 *            how often (in seconds) the synchronization of managed domains (in memory) with the domain subdirectories in the <code>domainsRoot</code> directory (on disk) is done. If
	 *            <code>domainSyncInterval</code> > 0, every <code>domainSyncInterval</code>, the managed domains (loaded in memory) are updated if any change has been detected in the
	 *            <code>domainsRoot</code> directory in this interval (since last sync). To be more specific, <i>any change</i> here means any creation/deletion/modification of a domain folder
	 *            (modification means: any file changed within the folder). If <code>domainSyncInterval</code> &lt;= 0, synchronization is disabled.
	 * @param pdpModelHandler
	 *            PDP configuration model handler
	 * @param useRandomAddressBasedUUID
	 *            true iff a random multicast address must be used as node field of generated UUIDs (Version 1), else the MAC address of one of the network interfaces is used. Setting this to 'true'
	 *            is NOT recommended unless the host is disconnected from the network. These generated UUIDs are used for domain IDs.
	 * @param domainDaoClientFactory
	 *            domain DAO client factory
	 * @param enablePdpOnly
	 *            enable only PDP-related operations (in particular, disable all PAP features)
	 * @param enableXacmlJsonProfile
	 *            enable support of XACML JSON Profile (standard XACML/JSON request/response format)
	 * @throws IOException
	 *             I/O error occurred scanning existing domain folders in {@code domainsRoot} for loading.
	 */
	@ConstructorProperties({ "domainsRoot", "domainTmpl", "domainsSyncIntervalSec", "pdpModelHandler", "enablePdpOnly", "enableXacmlJsonProfile", "useRandomAddressBasedUUID",
	        "domainDaoClientFactory" })
	public FlatFileBasedDomainsDao(final Resource domainsRoot, final Resource domainTmpl, final int domainsSyncIntervalSec, final PdpModelHandler pdpModelHandler, final boolean enablePdpOnly,
	        final boolean enableXacmlJsonProfile, final boolean useRandomAddressBasedUUID,
	        final DomainDaoClient.Factory<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT, FlatFileBasedDomainDao<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT>, DOMAIN_DAO_CLIENT> domainDaoClientFactory)
	        throws IOException
	{
		if (domainsRoot == null || domainTmpl == null || pdpModelHandler == null || domainDaoClientFactory == null)
		{
			throw ILLEGAL_CONSTRUCTOR_ARGS_EXCEPTION;
		}

		this.domainDaoClientFactory = domainDaoClientFactory;

		this.enablePdpOnly = enablePdpOnly;
		if (enablePdpOnly)
		{
			// disable PAP features
			this.policyDaoClientFactory = null;
			this.policyVersionDaoClientFactory = null;
		}
		else
		{
			this.policyDaoClientFactory = domainDaoClientFactory.getPolicyDaoClientFactory();
			this.policyVersionDaoClientFactory = policyDaoClientFactory.getVersionDaoClientFactory();
		}

		this.enableXacmlJsonProfile = enableXacmlJsonProfile;

		this.uuidGen = initUUIDGenerator(useRandomAddressBasedUUID);
		this.pdpModelHandler = pdpModelHandler;

		// Validate domainsRoot arg
		if (!domainsRoot.exists())
		{
			throw new IllegalArgumentException("'domainsRoot' resource does not exist: " + domainsRoot.getDescription());
		}

		final String ioExMsg = "Cannot resolve 'domainsRoot' resource '" + domainsRoot.getDescription() + "' as a file on the file system";
		final File domainsRootFile;
		try
		{
			domainsRootFile = domainsRoot.getFile();
		}
		catch (final IOException e)
		{
			throw new IllegalArgumentException(ioExMsg, e);
		}

		this.domainsRootDir = domainsRootFile.toPath();
		FlatFileDAOUtils.checkFile("File defined by SecurityDomainManager parameter 'domainsRoot'", domainsRootDir, true, true);

		// Validate domainTmpl directory arg
		if (!domainTmpl.exists())
		{
			throw new IllegalArgumentException("'domainTmpl' resource does not exist: " + domainTmpl.getDescription());
		}

		final String ioExMsg2 = "Cannot resolve 'domainTmpl' resource '" + domainTmpl.getDescription() + "' as a file on the file system";
		final File domainTmplFile;
		try
		{
			domainTmplFile = domainTmpl.getFile();
		}
		catch (final IOException e)
		{
			throw new IllegalArgumentException(ioExMsg2, e);
		}

		this.domainTmplDirPath = domainTmplFile.toPath();
		FlatFileDAOUtils.checkFile("File defined by SecurityDomainManager parameter 'domainTmpl'", domainTmplDirPath, true, false);

		LOGGER.debug("Looking for domain sub-directories in directory {}", domainsRootDir);
		try (DirectoryStream<Path> dirStream = Files.newDirectoryStream(domainsRootDir))
		{
			for (final Path domainPath : dirStream)
			{
				LOGGER.debug("Checking domain in file {}", domainPath);
				if (!Files.isDirectory(domainPath))
				{
					LOGGER.warn("Ignoring invalid domain file {} (not a directory)", domainPath);
					continue;
				}

				// domain folder name is the domain ID
				final Path lastPathSegment = domainPath.getFileName();
				if (lastPathSegment == null)
				{
					throw new RuntimeException("Invalid Domain folder path '" + domainPath + "': no filename");
				}

				final String domainId = lastPathSegment.toString();

				final DOMAIN_DAO_CLIENT domain = domainDaoClientFactory.getInstance(domainId, () -> {
					try
					{
						return new FileBasedDomainDaoImpl(domainPath, null);
					}
					catch (final IllegalArgumentException e)
					{
						throw new RuntimeException("Invalid domain data for domain '" + domainId + "'", e);
					}

				});

				domainMap.put(domainId, domain);
			}
		}
		catch (final IOException e)
		{
			throw new IOException("Failed to scan files in the domains root directory '" + domainsRootDir + "' looking for domain directories", e);
		}

		this.domainDirToMemSyncIntervalSec = Integer.valueOf(domainsSyncIntervalSec).longValue();
	}

	/**
	 * Close domains, i.e. PDPs, sync threads (to be called by Spring when application stopped)
	 */
	public void closeDomains()
	{
		synchronized (domainsRootDir)
		{
			for (final DOMAIN_DAO_CLIENT domain : domainMap.values())
			{
				try
				{
					final FlatFileBasedDomainDao<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT> domainDAO = domain.getDao();
					domainDAO.close();
				}
				catch (final Throwable t)
				{
					LOGGER.error("Error closing domain {}", domain.getDao().getDomainId(), t);
				}
			}
		}
	}

	@Override
	public DOMAIN_DAO_CLIENT getDomainDaoClient(final String domainId) throws IOException
	{
		if (domainId == null)
		{
			throw NULL_DOMAIN_ID_ARG_EXCEPTION;
		}

		/*
		 * Synchronized block two avoid that two threads adding the same desynced domain entry to the map
		 */
		synchronized (domainsRootDir)
		{
			final DOMAIN_DAO_CLIENT domain = domainMap.get(domainId);
			if (domain == null)
			{
				/*
				 * check whether domain directory exists (in case it is not synchronized with domain map
				 */
				final Path domainDir = this.domainsRootDir.resolve(domainId);

				if (Files.exists(domainDir))
				{
					return addDomainToCacheAfterDirectoryCreated(domainId, domainDir, null);
				}

			}

			return domain;
		}
	}

	@Override
	public String addDomain(final WritableDomainProperties props) throws IOException, IllegalArgumentException
	{
		if (this.enablePdpOnly)
		{
			throw DISABLED_OPERATION_EXCEPTION;
		}

		final UUID uuid = uuidGen.generate();
		/*
		 * Encode UUID with Base64url to have shorter IDs in REST API URL paths and to be compatible with filenames on any operating system, since the resulting domain ID is used as name for the
		 * directory where all the domain's data will be stored.
		 */
		final ByteBuffer byteBuf = ByteBuffer.wrap(new byte[16]);
		byteBuf.putLong(uuid.getMostSignificantBits());
		byteBuf.putLong(uuid.getLeastSignificantBits());
		final String domainId = FlatFileDAOUtils.base64UrlEncode(byteBuf.array());
		synchronized (domainsRootDir)
		{
			/*
			 * This should not happen if the UUID generator can be trusted, but - hey - we never know.
			 */
			if (this.domainMap.containsKey(domainId))
			{
				throw new ConcurrentModificationException(
				        "Generated domain ID conflicts (is same as) ID of existing domain (flawed domain UUID generator or ID generated in different way?): ID=" + domainId);
			}

			/*
			 * Check whether externalId already used
			 */
			final String newExternalId = props.getExternalId();
			if (newExternalId != null && domainIDsByExternalId.containsKey(newExternalId))
			{
				throw new IllegalArgumentException("externalId conflict: '" + newExternalId + "' cannot be associated with domainId '" + domainId + "' because already associated with another");
			}

			final Path domainDir = this.domainsRootDir.resolve(domainId);
			if (Files.notExists(domainDir))
			{
				/*
				 * Create/initialize new domain directory from domain template directory
				 */
				FlatFileDAOUtils.copyDirectory(this.domainTmplDirPath, domainDir, 3);
			}

			addDomainToCacheAfterDirectoryCreated(domainId, domainDir, props);
		}

		return domainId;
	}

	@Override
	public Set<String> getDomainIdentifiers(final String externalId) throws IOException
	{
		if (this.enablePdpOnly)
		{
			throw DISABLED_OPERATION_EXCEPTION;
		}

		synchronized (domainsRootDir)
		{
			if (externalId != null)
			{
				// externalId not null
				final String domainId = domainIDsByExternalId.get(externalId);
				if (domainId == null)
				{
					return Collections.emptySet();
				}

				// domainId not null, check if domain is still there in the
				// repository
				final Path domainDirPath = this.domainsRootDir.resolve(domainId);
				if (Files.exists(domainDirPath, LinkOption.NOFOLLOW_LINKS))
				{
					return Collections.singleton(domainId);
				}

				// domain directory no longer exists, remove from map and so on
				removeDomainFromCache(domainId);
				return Collections.emptySet();
			}

			// externalId == null
			/*
			 * All changes to domainMap are synchronized by 'domainsRootDir'. So we can iterate and change if necessary for synchronizing the domains root directory with the domainMap (Using a
			 * domainMap is necessary for quick access to domains' PDPs.)
			 */
			final Set<String> oldDomainIDs = new HashSet<>(domainMap.keySet());
			final Set<String> newDomainIDs = new HashSet<>();
			try (DirectoryStream<Path> dirStream = Files.newDirectoryStream(domainsRootDir))
			{
				for (final Path domainDirPath : dirStream)
				{
					LOGGER.debug("Checking domain in file {}", domainDirPath);
					if (!Files.isDirectory(domainDirPath))
					{
						LOGGER.warn("Ignoring invalid domain file {} (not a directory)", domainDirPath);
						continue;
					}

					// domain folder name is the domain ID
					final Path lastPathSegment = domainDirPath.getFileName();
					if (lastPathSegment == null)
					{
						throw new RuntimeException("Invalid Domain folder path '" + domainDirPath + "': no filename");
					}

					final String domainId = lastPathSegment.toString();
					newDomainIDs.add(domainId);
					if (oldDomainIDs.remove(domainId))
					{
						// not new domain, but directory may have changed ->
						// sync
						final DOMAIN_DAO_CLIENT domain = domainMap.get(domainId);
						if (domain != null)
						{
							domain.getDao().sync();
						}
					}
					else
					{
						// new domain directory
						addDomainToCacheAfterDirectoryCreated(domainId, domainDirPath, null);
					}
				}
			}
			catch (final IOException e)
			{
				throw new IOException("Failed to scan files in the domains root directory '" + domainsRootDir + "' looking for domain directories", e);
			}

			if (!oldDomainIDs.isEmpty())
			{
				// old domains remaining in cache that don't match directories
				// -> removed
				// -> remove from cache
				for (final String domainId : oldDomainIDs)
				{
					removeDomainFromCache(domainId);
				}
			}

			return newDomainIDs;
		}
	}

	@Override
	public boolean containsDomain(final String domainId) throws IOException
	{
		if (this.enablePdpOnly)
		{
			throw DISABLED_OPERATION_EXCEPTION;
		}

		if (domainId == null)
		{
			throw NULL_DOMAIN_ID_ARG_EXCEPTION;
		}

		/*
		 * Synchronized block two avoid that two threads adding the same desynced domain entry to the map
		 */
		synchronized (domainsRootDir)
		{
			final boolean isMatched = domainMap.containsKey(domainId);
			if (isMatched)
			{
				return true;
			}

			/*
			 * check whether domain directory exists (in case it is not synchronized with domain map
			 */
			final Path domainDir = this.domainsRootDir.resolve(domainId);
			if (Files.exists(domainDir))
			{
				addDomainToCacheAfterDirectoryCreated(domainId, domainDir, null);
				return true;
			}
		}

		return false;
	}

}
