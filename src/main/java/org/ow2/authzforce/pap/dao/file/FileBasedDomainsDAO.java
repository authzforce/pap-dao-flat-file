/**
 * Copyright (C) 2012-2015 Thales Services SAS.
 *
 * This file is part of AuthZForce.
 *
 * AuthZForce is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * AuthZForce is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with AuthZForce. If not, see <http://www.gnu.org/licenses/>.
 */
package org.ow2.authzforce.pap.dao.file;

import static java.nio.file.StandardWatchEventKinds.ENTRY_CREATE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_DELETE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY;
import static java.nio.file.StandardWatchEventKinds.OVERFLOW;

import java.beans.ConstructorProperties;
import java.io.File;
import java.io.FileFilter;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.WatchEvent;
import java.nio.file.WatchEvent.Kind;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.Collections;
import java.util.ConcurrentModificationException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NavigableSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import oasis.names.tc.xacml._3_0.core.schema.wd_17.IdReferenceType;
import oasis.names.tc.xacml._3_0.core.schema.wd_17.PolicySet;

import org.apache.commons.io.FileUtils;
import org.ow2.authzforce.core.pap.api.dao.DomainDAOClient;
import org.ow2.authzforce.core.pap.api.dao.DomainsDAO;
import org.ow2.authzforce.core.pap.api.dao.PolicyDAOClient;
import org.ow2.authzforce.core.pap.api.dao.PolicyVersionDAOClient;
import org.ow2.authzforce.core.pap.api.dao.ReadableDomainProperties;
import org.ow2.authzforce.core.pap.api.dao.TooManyPoliciesException;
import org.ow2.authzforce.core.pap.api.dao.WritableDomainProperties;
import org.ow2.authzforce.core.pdp.api.EnvironmentPropertyName;
import org.ow2.authzforce.core.pdp.api.JaxbXACMLUtils;
import org.ow2.authzforce.core.pdp.api.PDP;
import org.ow2.authzforce.core.pdp.api.PolicyVersion;
import org.ow2.authzforce.core.pdp.impl.DefaultEnvironmentProperties;
import org.ow2.authzforce.core.pdp.impl.PDPImpl;
import org.ow2.authzforce.core.pdp.impl.PdpConfigurationParser;
import org.ow2.authzforce.core.pdp.impl.PdpModelHandler;
import org.ow2.authzforce.core.xmlns.pdp.Pdp;
import org.ow2.authzforce.core.xmlns.pdp.StaticRefBasedRootPolicyProvider;
import org.ow2.authzforce.pap.dao.file.xmlns.DomainProperties;
import org.ow2.authzforce.pap.dao.file.xmlns.StaticFileBasedDAORefPolicyProvider;
import org.ow2.authzforce.xmlns.pdp.ext.AbstractAttributeProvider;
import org.ow2.authzforce.xmlns.pdp.ext.AbstractPolicyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.util.ResourceUtils;
import org.xml.sax.SAXException;

import com.fasterxml.uuid.EthernetAddress;
import com.fasterxml.uuid.Generators;
import com.fasterxml.uuid.impl.TimeBasedGenerator;

// import com.google.common.io.BaseEncoding;

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
public final class FileBasedDomainsDAO<VERSION_DAO_CLIENT extends PolicyVersionDAOClient, POLICY_DAO_CLIENT extends PolicyDAOClient, DOMAIN_DAO_CLIENT extends DomainDAOClient<FileBasedDomainDAO<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT>>>
		implements DomainsDAO<DOMAIN_DAO_CLIENT>
{

	private static class ReadableDomainPropertiesImpl implements ReadableDomainProperties
	{

		private final String domainId;
		private final IdReferenceType rootPolicyRef;
		private final String description;
		private final String externalId;

		private ReadableDomainPropertiesImpl(String domainId, String description, String externalId, IdReferenceType rootPolicyRef)
		{
			assert domainId != null;
			assert rootPolicyRef != null;

			this.domainId = domainId;
			this.rootPolicyRef = rootPolicyRef;
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

		@Override
		public IdReferenceType getRootPolicyRef()
		{
			return rootPolicyRef;
		}

	}

	private static final IllegalArgumentException ILLEGAL_CONSTRUCTOR_ARGS_EXCEPTION = new IllegalArgumentException(
			"One of the following FileBasedDomainsDAO constructor arguments is undefined although required: domainsRoot == null || domainTmpl == null || schema == null || pdpModelHandler == null || domainDAOClientFactory == null || policyDAOClientFactory == null");

	private static final IllegalArgumentException NULL_DOMAIN_ID_ARG_EXCEPTION = new IllegalArgumentException("Undefined domain ID arg");

	private static final Logger LOGGER = LoggerFactory.getLogger(FileBasedDomainsDAO.class);

	private static final IllegalArgumentException NULL_POLICY_ARGUMENT_EXCEPTION = new IllegalArgumentException("Null policySet arg");
	private static final TreeSet<PolicyVersion> EMPTY_TREE_SET = new TreeSet<>();
	private static final IllegalArgumentException NULL_DOMAIN_PROPERTIES_ARGUMENT_EXCEPTION = new IllegalArgumentException("Null domain properties arg");
	private static final IllegalArgumentException NULL_ATTRIBUTE_PROVIDERS_ARGUMENT_EXCEPTION = new IllegalArgumentException("Null attributeProviders arg");

	/**
	 * Domain properties XSD location
	 */
	public static final String DOMAIN_PROPERTIES_XSD_LOCATION = "classpath:org.ow2.authzforce.pap.dao.file.properties.xsd";

	/**
	 * Name of domain properties file
	 */
	public static final String DOMAIN_PROPERTIES_FILENAME = "properties.xml";

	/**
	 * Name of PDP configuration file
	 */
	public static final String DOMAIN_PDP_CONFIG_FILENAME = "pdp.xml";

	/**
	 * Must start with a non-base64url character
	 */
	public static final String FILE_BACKUP_SUFFIX = ".old";

	// private static final Logger LOGGER = LoggerFactory.getLogger(SecurityDomain.class);

	private static final JAXBContext DOMAIN_PROPERTIES_JAXB_CONTEXT;
	static
	{
		try
		{
			DOMAIN_PROPERTIES_JAXB_CONTEXT = JAXBContext.newInstance(DomainProperties.class);
		} catch (JAXBException e)
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
		} catch (FileNotFoundException e)
		{
			throw new RuntimeException("Domain properties schema not found", e);
		} catch (SAXException e)
		{
			throw new RuntimeException("Invalid domain properties schema file", e);
		}
	}

	private static final FileFilter DIRECTORY_FILTER = new FileFilter()
	{

		@Override
		public boolean accept(File pathname)
		{
			return pathname.isDirectory();
		}

	};

	private final TimeBasedGenerator uuidGen;

	/**
	 * Initializes a UUID generator that generates UUID version 1. It is thread-safe and uses the host MAC address as the node field if
	 * useRandomAddressBasedUUID = false, in which case UUID uniqueness across multiple hosts (e.g. in a High-Availability architecture) is guaranteed. If this
	 * is used by multiple hosts to generate UUID for common objects (e.g. in a High Availability architecture), it is critical that clocks of all hosts be
	 * synchronized (e.g. with a common NTP server). If no MAC address is available, e.g. no network connection, set useRandomAddressBasedUUID = true to use a
	 * random multicast address instead as node field.
	 * 
	 * @see <a href="http://www.cowtowncoder.com/blog/archives/2010/10/entry_429.html">More on Java UUID Generator (JUG), a word on performance</a>
	 * @see <a href="http://johannburkard.de/blog/programming/java/Java-UUID-generators-compared.html">Java UUID generators compared</a>
	 * 
	 * @return UUID v1
	 */
	private static TimeBasedGenerator initUUIDGenerator(boolean useRandomAddressBasedUUID)
	{

		final EthernetAddress macAddress;
		if (useRandomAddressBasedUUID)
		{
			macAddress = EthernetAddress.constructMulticastAddress();
		} else
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

	private final Path domainsRootDir;

	/**
	 * Maps domainId to domain
	 */
	private final ConcurrentMap<String, DOMAIN_DAO_CLIENT> domainMap = new ConcurrentHashMap<>();

	/**
	 * Maps domain externalId to unique API-defined domainId in domainMap keys
	 */
	private final ConcurrentMap<String, String> domainIDsByExternalId = new ConcurrentHashMap<>();

	private final File domainTmplDir;

	private final PdpModelHandler pdpModelHandler;

	private final ScheduledExecutorService domainsFolderSyncTaskScheduler;

	private final int domainsFolderSyncIntervalSec;

	private final WatchService domainsFolderWatcher;

	private final DomainDAOClient.Factory<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT, FileBasedDomainDAO<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT>, DOMAIN_DAO_CLIENT> domainDAOClientFactory;
	private final PolicyDAOClient.Factory<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT> policyDAOClientFactory;
	private final PolicyVersionDAOClient.Factory<VERSION_DAO_CLIENT> policyVersionDAOClientFactory;

	private final int maxNumOfPoliciesPerDomain;

	private final int maxNumOfVersionsPerPolicy;

	private final TooManyPoliciesException maxNumOfPoliciesReachedException;

	private final TooManyPoliciesException maxNumOfVersionsReachedException;

	private ReadableDomainProperties removeDomainFromMapsAfterDirectoryDeleted(ReadableDomainProperties domainProps) throws IOException
	{
		assert domainProps.getInternalId() != null;

		final DOMAIN_DAO_CLIENT domainDAOClient = domainMap.remove(domainProps.getInternalId());
		if (domainDAOClient == null)
		{
			return null;
		}

		final String domainExternalId = domainProps.getExternalId();
		if (domainExternalId != null)
		{
			domainIDsByExternalId.remove(domainExternalId);
		}

		return domainProps;
	}

	private final class FileBasedDomainDAOImpl implements FileBasedDomainDAO<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT>
	{

		private final String domainId;

		private final File domainDir;

		private final File propFile;

		private final File pdpConfFile;

		private final File policyParentDirectory;
		private final String policyFilenameSuffix;

		private final FileFilter policyFilenameFilter = new FileFilter()
		{

			@Override
			public boolean accept(File file)
			{
				return file.isFile() && file.getName().endsWith(policyFilenameSuffix);
			}
		};

		private volatile PDPImpl pdp;

		private final DefaultEnvironmentProperties pdpConfEnvProps;

		/**
		 * Constructs end-user policy admin domain
		 * 
		 * @param domainDir
		 *            domain directory
		 * @param jaxbCtx
		 *            JAXB context for marshalling/unmarshalling configuration data
		 * @param confSchema
		 *            domain's XML configuration schema
		 * @param pdpModelHandler
		 *            PDP configuration model handler
		 * @param domainMapEntry
		 *            proxy to entry in domains map where all domains are registry (e.g. to self-remove from the map)
		 * @param props
		 *            new domain properties for new domain creation, null if no specific properties (use default properties)
		 * @throws IllegalArgumentException
		 *             Invalid configuration files in {@code domainDir}
		 * @throws IOException
		 *             Error loading configuration file(s) from or persisting {@code props} (if not null) to {@code domainDir}
		 */
		private FileBasedDomainDAOImpl(File domainDir, WritableDomainProperties props) throws IOException
		{
			assert domainDir != null;

			this.domainId = domainDir.getName();

			// domainDir
			FileBasedDAOUtils.checkFile("Domain directory", domainDir, true, true);
			this.domainDir = domainDir;

			// PDP configuration parser environment properties, e.g. PARENT_DIR for replacement in configuration strings
			this.pdpConfEnvProps = new DefaultEnvironmentProperties(Collections.singletonMap(EnvironmentPropertyName.PARENT_DIR, domainDir.toURI().toString()));

			// PDP config file
			this.pdpConfFile = new File(domainDir, DOMAIN_PDP_CONFIG_FILENAME);

			// Get policy directory from PDP conf (refPolicyProvider/policyLocation pattern)
			final Pdp pdpConf = getPDPConfTmpl();

			// Get the refpolicies parent directory and suffix from PDP conf (refPolicyProvider)
			final AbstractPolicyProvider refPolicyProvider = pdpConf.getRefPolicyProvider();
			if (!(refPolicyProvider instanceof StaticFileBasedDAORefPolicyProvider))
			{
				// critical error
				throw new RuntimeException("Invalid PDP configuration of domain '" + domainId + "' in file '" + pdpConfFile
						+ "': refPolicyProvider is not an instance of " + StaticFileBasedDAORefPolicyProvider.class + " as expected.");
			}

			final StaticFileBasedDAORefPolicyProvider fileBasedRefPolicyProvider = (StaticFileBasedDAORefPolicyProvider) refPolicyProvider;
			// replace any ${PARENT_DIR} placeholder in policy location pattern
			final String policyLocation = pdpConfEnvProps.replacePlaceholders(fileBasedRefPolicyProvider.getPolicyLocationPattern());
			final Entry<File, String> result = FileBasedDAORefPolicyProviderModule.validateConf(policyLocation);
			this.policyParentDirectory = result.getKey();
			FileBasedDAOUtils.checkFile("Domain policies directory", policyParentDirectory, true, true);

			this.policyFilenameSuffix = result.getValue();

			// propFile
			this.propFile = new File(domainDir, DOMAIN_PROPERTIES_FILENAME);
			if (props != null)
			{
				// set/save properties and update PDP
				setDomainProperties(props.getDescription(), props.getExternalId(), props.getRootPolicyRef(), pdpConf);
			} else
			{
				// just load the PDP from the files
				reloadPDP();
			}
		}

		@Override
		public void reloadPDP() throws IOException, IllegalArgumentException
		{
			FileBasedDAOUtils.checkFile("Domain PDP configuration file", pdpConfFile, false, true);
			// test if PDP conf valid, and update the domain's PDP only if valid
			final PDPImpl newPDP = PdpConfigurationParser.getPDP(pdpConfFile, pdpModelHandler);
			// did not throw exception, so valid
			// update the domain's PDP
			if (pdp != null)
			{
				pdp.close();
			}

			pdp = newPDP;
		}

		/**
		 * 
		 * @param pdpConfTemplate
		 *            original PDP configuration template from file, i.e. before any replacement of property placeholders like ${PARENT_DIR}; saved/marshalled
		 *            to file PDP update succeeds
		 * @throws IllegalArgumentException
		 * @throws IOException
		 */
		private void updatePDP(Pdp pdpConfTmpl) throws IllegalArgumentException, IOException
		{
			// test if PDP conf valid, and update the domain's PDP only if valid
			final PDPImpl newPDP = PdpConfigurationParser.getPDP(pdpConfTmpl, pdpConfEnvProps);
			// did not throw exception, so valid
			// Commit/save the new PDP conf
			try
			{
				pdpModelHandler.marshal(pdpConfTmpl, pdpConfFile);
			} catch (JAXBException e)
			{
				// critical error: we should not end up with an invalid PDP configuration file, so we consider an I/O error
				throw new IOException("Error writing new PDP configuration of domain '" + domainId + "'", e);
			}

			// update the domain's PDP
			if (pdp != null)
			{
				pdp.close();
			}

			pdp = newPDP;
		}

		private void setProperties(String description, String externalId) throws IOException
		{
			final Marshaller marshaller;
			try
			{
				marshaller = DOMAIN_PROPERTIES_JAXB_CONTEXT.createMarshaller();
				marshaller.setProperty(Marshaller.JAXB_ENCODING, StandardCharsets.UTF_8.name());
			} catch (JAXBException e)
			{
				// critical error
				throw new RuntimeException("Error creating JAXB unmarshaller for domain properties (XML)", e);
			}

			marshaller.setSchema(DOMAIN_PROPERTIES_SCHEMA);
			try
			{
				/*
				 * The rootPolicyRef is in another file (PDP configuration file). We cannot marshall more generic ManagedResourceProperties because it does not
				 * have @XmlRootElement
				 */
				marshaller.marshal(new DomainProperties(description, externalId), propFile);
			} catch (JAXBException e)
			{
				throw new IOException("Error persisting properties (XML) of domain '" + domainId + "'", e);
			}
		}

		private DomainProperties getProperties() throws IOException
		{
			final Unmarshaller unmarshaller;
			try
			{
				unmarshaller = DOMAIN_PROPERTIES_JAXB_CONTEXT.createUnmarshaller();
			} catch (JAXBException e)
			{
				// critical error
				throw new RuntimeException("Error creating JAXB unmarshaller for domain properties (XML)", e);
			}

			unmarshaller.setSchema(DOMAIN_PROPERTIES_SCHEMA);
			final JAXBElement<DomainProperties> jaxbElt;
			try
			{
				jaxbElt = unmarshaller.unmarshal(new StreamSource(propFile), DomainProperties.class);
			} catch (JAXBException e)
			{
				throw new IOException("Error getting properties (XML) of domain '" + domainId + "'", e);
			}

			return jaxbElt.getValue();
		}

		/**
		 * Gets original PDP configuration template from file, before any replacement of property placeholders like ${PARENT_DIR}
		 * 
		 * @return original PDP configuration from file (no property like PARENT_DIR replaced in the process)
		 * @throws IOException
		 */
		private Pdp getPDPConfTmpl() throws IOException
		{
			try
			{
				return pdpModelHandler.unmarshal(new StreamSource(pdpConfFile), Pdp.class);
			} catch (JAXBException e)
			{
				// critical error: we should not end up with an invalid PDP configuration file, so we consider an I/O error
				throw new IOException("Error reading PDP configuration of domain '" + domainId + "'", e);
			}
		}

		private ReadableDomainProperties setDomainProperties(String description, String externalId, IdReferenceType rootPolicyRef, Pdp pdpConf)
				throws IOException, IllegalArgumentException
		{
			// Validate the PDP with new rootPolicyRef first if there is any
			final AbstractPolicyProvider rootPolicyProvider = pdpConf.getRootPolicyProvider();
			if (!(rootPolicyProvider instanceof StaticRefBasedRootPolicyProvider))
			{
				// critical error
				throw new RuntimeException("Invalid PDP configuration of domain '" + domainId + "'" + "': rootPolicyProvider is not an instance of "
						+ StaticRefBasedRootPolicyProvider.class + " as expected.");
			}

			final StaticRefBasedRootPolicyProvider staticRefBasedRootPolicyProvider = (StaticRefBasedRootPolicyProvider) rootPolicyProvider;
			// Do nothing if rootPolicyRef is the same/unchanged (loading a new PDP is costly)
			if (rootPolicyRef != null && !rootPolicyRef.equals(staticRefBasedRootPolicyProvider.getPolicyRef()))
			{
				// new rootPolicyRef different from old
				staticRefBasedRootPolicyProvider.setPolicyRef(rootPolicyRef);
				updatePDP(pdpConf);
			} else if (pdp == null)
			{
				// PDP not yet instantiated
				updatePDP(pdpConf);
			}

			// Update non-PDP properties
			// Get old externalId first for updating externalId later
			final DomainProperties oldProps = getProperties();
			final String oldExternalId = oldProps.getExternalId();
			setProperties(description, externalId);

			if (externalId != null && !externalId.equals(oldExternalId))
			{
				if (oldExternalId != null)
				{
					// verify oldExternalId valid for domainId
					final String matchingDomainId = domainIDsByExternalId.get(oldExternalId);
					if (!domainId.equals(matchingDomainId))
					{
						// wrong oldExternalId - this is critical and should not happen, unless the properties file was changed manually
						throw new RuntimeException("Failed to update externalId of domain '" + domainId + "': wrong oldExternalId arg = " + oldExternalId);
					}

					domainIDsByExternalId.remove(oldExternalId);
				}

				domainIDsByExternalId.put(externalId, domainId);
			}

			return new ReadableDomainPropertiesImpl(domainId, description, externalId, staticRefBasedRootPolicyProvider.getPolicyRef());
		}

		/**
		 * Get domain properties
		 * 
		 * @return domain properties
		 * @throws IOException
		 *             Error unmarshalling properties from XML files in domain directory
		 */
		@Override
		public ReadableDomainProperties getDomainProperties() throws IOException
		{
			final DomainProperties props = getProperties();

			// Get rootPolicyRef from PDP conf
			final Pdp pdpConf = getPDPConfTmpl();
			final AbstractPolicyProvider rootPolicyProvider = pdpConf.getRootPolicyProvider();
			if (!(rootPolicyProvider instanceof StaticRefBasedRootPolicyProvider))
			{
				// critical error
				throw new RuntimeException("Invalid PDP configuration of domain '" + domainId + "'" + "': rootPolicyProvider is not an instance of "
						+ StaticRefBasedRootPolicyProvider.class + " as expected.");
			}

			final StaticRefBasedRootPolicyProvider staticRefBasedRootPolicyProvider = (StaticRefBasedRootPolicyProvider) rootPolicyProvider;
			return new ReadableDomainPropertiesImpl(domainId, props.getDescription(), props.getExternalId(), staticRefBasedRootPolicyProvider.getPolicyRef());
		}

		@Override
		public ReadableDomainProperties setDomainProperties(WritableDomainProperties domainProperties) throws IOException, IllegalArgumentException
		{
			if (domainProperties == null)
			{
				throw NULL_DOMAIN_PROPERTIES_ARGUMENT_EXCEPTION;
			}

			// Synchronize changes on PDP (and other domain conf data) from multiple threads, keep minimal things in the synchronized block
			synchronized (domainDir)
			{
				final Pdp pdpConf = getPDPConfTmpl();
				return setDomainProperties(domainProperties.getDescription(), domainProperties.getExternalId(), domainProperties.getRootPolicyRef(), pdpConf);
			}

		}

		/**
		 * Returns the PDP enforcing the domain policy
		 * 
		 * @return domain PDP
		 */
		@Override
		public PDP getPDP()
		{
			return this.pdp;
		}

		/**
		 * Get domain PDP attribute providers
		 * 
		 * @return attribute providers
		 * @throws IOException
		 */
		@Override
		public List<AbstractAttributeProvider> getAttributeProviders() throws IOException
		{
			final Pdp pdpConf = getPDPConfTmpl();
			return pdpConf.getAttributeProviders();
		}

		@Override
		public List<AbstractAttributeProvider> setAttributeProviders(List<AbstractAttributeProvider> attributeproviders) throws IOException,
				IllegalArgumentException
		{
			if (attributeproviders == null)
			{
				throw NULL_ATTRIBUTE_PROVIDERS_ARGUMENT_EXCEPTION;
			}

			// Synchronize changes on PDP (and other domain conf data) from multiple threads, keep minimal things in the synchronized block
			synchronized (domainDir)
			{
				final Pdp pdpConf = getPDPConfTmpl();
				pdpConf.getAttributeProviders().clear();
				pdpConf.getAttributeProviders().addAll(attributeproviders);
				updatePDP(pdpConf);
			}

			return attributeproviders;
		}

		@Override
		public Set<String> getPolicyIDs() throws IOException
		{
			/*
			 * We could cache this, but note that caching may be taking place upfront already. For instance, if this is used behind a HTTP API, the result may
			 * be cached by the HTTP server or web framework already. For instance, you can enable server-side caching in CXF JAXRS framework with Ehcache-web.
			 */
			final File[] directories = policyParentDirectory.listFiles(DIRECTORY_FILTER);
			if (directories == null)
			{
				throw new IOException("Error listing files in policies directory '" + policyParentDirectory + "' of domain '" + domainId + "'");
			}

			final Set<String> policyIds = new HashSet<>(directories.length);
			for (final File directory : directories)
			{
				final String policyDirName = directory.getName();
				final String policyId;
				try
				{
					policyId = FileBasedDAOUtils.base64UrlDecode(policyDirName);
				} catch (IllegalArgumentException e)
				{
					throw new RuntimeException("Invalid policy directory name (bad encoding): " + policyDirName);
				}

				policyIds.add(policyId);
			}

			return policyIds;
		}

		/**
		 * Get policy-specific directory
		 * 
		 * @param policyId
		 * @return policy directory (created or not, i.e. to be created)
		 */
		private File getPolicyDirectory(String policyId)
		{
			assert policyId != null;
			// Name of directory is base64url-encoded policyID (no padding)
			final String policyDirName = FileBasedDAOUtils.base64UrlEncode(policyId);
			return new File(this.policyParentDirectory, policyDirName);
		}

		private File getPolicyVersionFile(File policyDirectory, String versionId)
		{
			return new File(policyDirectory, versionId + policyFilenameSuffix);
		}

		private File getPolicyVersionFile(String policyId, String versionId)
		{
			return new File(getPolicyDirectory(policyId), versionId + policyFilenameSuffix);
		}

		@Override
		public PolicySet addPolicy(PolicySet policySet) throws IOException, IllegalArgumentException, TooManyPoliciesException
		{
			if (policySet == null)
			{
				throw NULL_POLICY_ARGUMENT_EXCEPTION;
			}

			final String policyId = policySet.getPolicySetId();
			final File policyDir = getPolicyDirectory(policyId);
			final File policyVersionFile = getPolicyVersionFile(policyDir, policySet.getVersion());

			synchronized (domainDir)
			{
				if (policyDir.exists())
				{
					if (policyVersionFile.exists())
					{
						// conflict: some policy with same ID and version already exists, return it
						return getPolicy(policyVersionFile);
					}

					// new policy version
					// check whether limit of number of versions is reached
					if (maxNumOfVersionsPerPolicy > 0)
					{
						final NavigableSet<PolicyVersion> policyVersions = getPolicyVersions(policyDir);
						if (policyVersions.size() > maxNumOfVersionsPerPolicy)
						{
							// too many versions, we cannot just delete old versions because the root policy may reference one of them
							throw maxNumOfVersionsReachedException;
						}
					}
				} else
				{
					// new policy (and new version a fortiori)
					// check whether limit of number of policies is reached
					if (maxNumOfPoliciesPerDomain > 0)
					{
						final File[] directories = policyParentDirectory.listFiles(DIRECTORY_FILTER);
						if (directories == null)
						{
							throw new IOException("Error listing files in policies directory '" + policyParentDirectory + "' of domain '" + domainId + "'");
						}

						if (directories.length > maxNumOfPoliciesPerDomain)
						{
							throw maxNumOfPoliciesReachedException;
						}
					}

					if (!policyDir.mkdir())
					{
						throw new IOException("Error creating directory '" + policyDir + "' for new policy '" + policyId + "' in domain '" + domainId + "'");
					}
				}

				writePolicy(policySet, policyVersionFile);

				// Reload PDP with the new policy
				try
				{
					reloadPDP();
					// PDP reloaded successfully, we can safely delete
				} catch (Throwable e)
				{
					// PDP reload failed -> rollback
					if (!policyVersionFile.delete())
					{
						throw new IOException("Failed to delete file of invalid policy that caused PDP instantiation failure: '" + policyVersionFile
								+ "'. Please delete manually.", e);
					}

					throw e;
				}
			}

			return null;
		}

		@Override
		public ReadableDomainProperties removeDomain() throws IOException
		{
			synchronized (domainDir)
			{
				final ReadableDomainProperties domainProps = getDomainProperties();
				FileUtils.deleteDirectory(domainDir);
				if (pdp != null)
				{
					pdp.close();
				}
				return removeDomainFromMapsAfterDirectoryDeleted(domainProps);
			}
		}

		@Override
		public POLICY_DAO_CLIENT getPolicyDAOClient(String policyId)
		{
			if (policyId == null)
			{
				return null;
			}

			return policyDAOClientFactory.getInstance(policyId, this);
		}

		/**
		 * Get policy versions from policy directory from latest to oldest
		 * 
		 * @param policyDirectory
		 * @return versions; empty if directory does not exist or is not a directory
		 * @throws IOException
		 */
		private NavigableSet<PolicyVersion> getPolicyVersions(File policyDirectory) throws IOException
		{
			assert policyDirectory != null;

			if (!policyDirectory.exists() || !policyDirectory.isDirectory())
			{
				return EMPTY_TREE_SET;
			}

			final File[] files = policyDirectory.listFiles(policyFilenameFilter);
			if (files == null)
			{
				throw new IOException("Error listing policy version files in policy directory '" + policyDirectory + "' of domain '" + domainId + "'");
			}

			final TreeSet<PolicyVersion> versions = new TreeSet<>(Collections.reverseOrder());
			for (final File file : files)
			{
				final String versionPlusSuffix = file.getName();
				final String versionId = versionPlusSuffix.substring(0, versionPlusSuffix.length() - policyFilenameSuffix.length());
				final PolicyVersion version = new PolicyVersion(versionId);
				versions.add(version);
			}

			return versions;
		}

		@Override
		public NavigableSet<PolicyVersion> getPolicyVersions(String policyId) throws IOException
		{
			if (policyId == null)
			{
				return EMPTY_TREE_SET;
			}

			/*
			 * We could cache this, but note that caching may be taking place upfront already. For instance, if this is used behind a HTTP API, the result may
			 * be cached by the HTTP server or web framework already. For instance, you can enable server-side caching in CXF JAXRS framework with Ehcache-web.
			 */
			final File policyDir = getPolicyDirectory(policyId);
			return getPolicyVersions(policyDir);
		}

		@Override
		public NavigableSet<PolicyVersion> removePolicy(String policyId) throws IOException, IllegalArgumentException
		{
			if (policyId == null)
			{
				return EMPTY_TREE_SET;
			}

			final File policyDir = getPolicyDirectory(policyId);
			final NavigableSet<PolicyVersion> versions = getPolicyVersions(policyDir);
			if (versions.isEmpty())
			{
				// nothing to remove
				return EMPTY_TREE_SET;
			}

			synchronized (domainDir)
			{
				/*
				 * Try reload PDP without the policy (directory) to see if it can be removed safely, i.e. it is no longer used/required
				 */
				final File tmpBackupFile = new File(domainDir, policyDir.getName() + FILE_BACKUP_SUFFIX);
				if (!policyDir.renameTo(tmpBackupFile))
				{
					throw new IOException("Error creating policy file backup before removal: " + policyDir + " -> " + tmpBackupFile);
				}

				try
				{
					reloadPDP();
					// PDP reloaded successfully, we can safely delete
					FileUtils.deleteDirectory(tmpBackupFile);
				} catch (Throwable e)
				{
					// PDP reload failed -> rollback
					if (!tmpBackupFile.renameTo(policyDir))
					{
						throw new IOException("Error restoring policy file from backup after failed removal (causing PDP instantiation failure): "
								+ tmpBackupFile + " -> " + policyDir);
					}
					
					// the request to remove the policy is not legit (PDP needs it)
					throw new IllegalArgumentException("Policy '" + policyId + "' cannot be removed because it is still used as root policy, or referenced directly/indirectly by the root policy", e);
				}
			}
			return versions;
		}

		@Override
		public VERSION_DAO_CLIENT getVersionDAOClient(String policyId, String version)
		{
			if (policyId == null || version == null)
			{
				return null;
			}

			return policyVersionDAOClientFactory.getInstance(policyId, version, this);
		}

		/**
		 * Get policy from file
		 * 
		 * @param policyFile
		 * @return policy; null if policyFile does not exists or is not a file
		 * @throws IOException
		 */
		private PolicySet getPolicy(File policyFile) throws IOException
		{
			assert policyFile != null;

			if (!policyFile.exists() || !policyFile.isFile())
			{
				return null;
			}

			final JAXBElement<PolicySet> policyElt;
			try
			{
				final Unmarshaller unmarshaller = JaxbXACMLUtils.createXacml3Unmarshaller();
				policyElt = unmarshaller.unmarshal(new StreamSource(policyFile), PolicySet.class);
			} catch (JAXBException e)
			{
				throw new IOException("Error getting a policy of domain '" + domainId + "'", e);
			}

			return policyElt.getValue();
		}

		/**
		 * Write policy to file
		 * 
		 * @param file
		 *            target file
		 * @throws IOException
		 */
		private void writePolicy(PolicySet policy, File file) throws IOException
		{
			assert policy != null;
			assert file != null;

			try
			{
				final Marshaller marshaller = JaxbXACMLUtils.createXacml3Marshaller();
				marshaller.marshal(policy, file);
			} catch (JAXBException e)
			{
				throw new IOException("Error saving policy in domain '" + domainId + "'", e);
			}
		}

		@Override
		public PolicySet getPolicyVersion(String policyId, String version) throws IOException
		{
			if (policyId == null || version == null)
			{
				return null;
			}

			final File policyVersionFile = getPolicyVersionFile(policyId, version);
			return getPolicy(policyVersionFile);
		}

		@Override
		public PolicySet removePolicyVersion(String policyId, String version) throws IOException, IllegalArgumentException
		{
			if (policyId == null || version == null)
			{
				return null;
			}

			final File policyVersionFile = getPolicyVersionFile(policyId, version);
			final PolicySet policy = getPolicy(policyVersionFile);
			if (policy == null)
			{
				return null;
			}

			// Reload PDP without the policy (version)
			final File tmpBackupFile = new File(policyVersionFile.getParentFile(), policyVersionFile.getName() + FILE_BACKUP_SUFFIX);
			synchronized (domainDir)
			{
				if (!policyVersionFile.renameTo(tmpBackupFile))
				{
					throw new IOException("Failed to make policy backup file before removal: '" + policyVersionFile + "' -> '" + tmpBackupFile);
				}
				try
				{
					reloadPDP();
					// PDP reloaded successfully, we can safely delete
					if (!tmpBackupFile.delete())
					{
						throw new IOException("Failed to delete policy backup file: '" + tmpBackupFile + "'. Please delete manually.");
					}

				} catch (Throwable e)
				{
					// PDP reload failed -> rollback
					if (!tmpBackupFile.renameTo(policyVersionFile))
					{
						throw new IOException("Failed to restore policy backup file after failed removal (causing PDP instantiation failure): '"
								+ tmpBackupFile + "' -> '" + policyVersionFile);
					}

					throw e;
				}
			}

			return policy;
		}
	}

	/**
	 * Create domain DAO and register it in the map (incl. domainIDsByExternalId if props != null && props.getExternalId() != null)
	 * 
	 * @param domainId
	 * @param domainDirectory
	 * @param props
	 *            (optional), specific domain properties, or null if default or no properties should be used
	 * @throws IOException
	 */
	private void addDomainToMapsAfterDirectoryCreated(String domainId, File domainDirectory, WritableDomainProperties props) throws IOException
	{
		final FileBasedDomainDAO<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT> domainDAO = new FileBasedDomainDAOImpl(domainDirectory, props);
		final DOMAIN_DAO_CLIENT domainDAOClient = domainDAOClientFactory.getInstance(domainId, domainDAO);
		this.domainMap.put(domainId, domainDAOClient);

		if (props == null)
		{
			return;
		}

		// props != null
		final String domainExternalId = props.getExternalId();
		if (domainExternalId != null)
		{
			domainIDsByExternalId.put(domainExternalId, domainId);
		}
	}

	@SuppressWarnings("unchecked")
	private static <T> WatchEvent<T> cast(WatchEvent<?> event)
	{
		return (WatchEvent<T>) event;
	}

	private final class DomainsFolderSyncTask implements Runnable
	{
		private final Map<Path, WatchEvent.Kind<?>> domainFolderToEventMap = new HashMap<>();
		private final Map<WatchKey, Path> domainsFolderWatchKeys = new HashMap<>();

		/**
		 * Register the given directory with the WatchService
		 */
		private void addWatchedDirectory(Path dir)
		{
			final WatchKey key;
			try
			{
				key = dir.register(domainsFolderWatcher, ENTRY_CREATE, ENTRY_DELETE, ENTRY_MODIFY);
			} catch (IOException ex)
			{
				throw new RuntimeException("Failed to register directory '" + dir + "' with WatchService for synchronization", ex);
			}

			if (LOGGER.isDebugEnabled())
			{
				final Path prev = this.domainsFolderWatchKeys.get(key);
				if (prev == null)
				{
					LOGGER.debug("register watch key: {}", dir);
				} else
				{
					if (!dir.equals(prev))
					{
						LOGGER.debug("update watch key: {} -> {}", prev, dir);
					}
				}
			}

			this.domainsFolderWatchKeys.put(key, dir);
		}

		@Override
		public void run()
		{
			try
			{
				LOGGER.debug("Executing synchronization task...");
				WatchKey key;
				// try {
				// key = watcher.take();
				// if(key == null) {
				// continue;
				// }
				// } catch (InterruptedException x) {
				// // throw new RuntimeException(x);
				// return;
				// }
				// poll all pending watch keys
				while ((key = domainsFolderWatcher.poll()) != null)
				{

					final Path dir = domainsFolderWatchKeys.get(key);
					if (dir == null)
					{
						LOGGER.error("Watch key does not match any registered directory");
						continue;
					}

					LOGGER.debug("Processing watch key for path: {}", dir);

					for (final WatchEvent<?> event : key.pollEvents())
					{
						final WatchEvent.Kind<?> kind = event.kind();

						if (kind == OVERFLOW)
						{
							LOGGER.error("Some watch event might have been lost or discarded. Consider restarting the application to force reset synchronization state and reduce the sync interval.");
							continue;
						}

						// Context for directory entry event is the file name of
						// entry
						final WatchEvent<Path> ev = cast(event);
						final Path childRelativePath = ev.context();
						final Path childAbsPath = dir.resolve(childRelativePath);

						// print out event
						LOGGER.info("Domains folder change detected: {}: {}", event.kind().name(), childRelativePath);

						// if directory is created, and watching recursively,
						// then
						// register it and its sub-directories
						if (/* recursive && */kind == ENTRY_CREATE && Files.isDirectory(childAbsPath, LinkOption.NOFOLLOW_LINKS))
						{
							// registerAll(child);
							addWatchedDirectory(childAbsPath);
						}

						// MONITORING DOMAIN FOLDERS
						if (dir.equals(domainsRootDir))
						{
							// child of root folder (domains) created or deleted
							// (ignore modify at
							// this
							// level)
							// && evaluated before ||
							if (kind == ENTRY_CREATE && Files.isDirectory(childAbsPath, LinkOption.NOFOLLOW_LINKS) || kind == ENTRY_DELETE)
							{
								domainFolderToEventMap.put(childAbsPath, kind);
							}
						} else
						{
							/*
							 * modify on subfolder (domain) If no CREATE event already registered in map, register MODIFY
							 */
							final WatchEvent.Kind<?> eventKind = domainFolderToEventMap.get(dir);
							if (eventKind != ENTRY_CREATE)
							{
								domainFolderToEventMap.put(dir, ENTRY_MODIFY);
							}
						}
					}

					// reset key and remove from set if directory no longer
					// accessible
					final boolean valid = key.reset();
					if (!valid)
					{
						domainsFolderWatchKeys.remove(key);

						// all directories are inaccessible
						if (domainsFolderWatchKeys.isEmpty())
						{
							break;
						}
					}
				}

				// do the actions according to map
				LOGGER.debug("Synchronization events to be handled: {}", domainFolderToEventMap);
				for (final Entry<Path, Kind<?>> domainFolderToEventEntry : domainFolderToEventMap.entrySet())
				{
					final Path domainDirPath = domainFolderToEventEntry.getKey();
					final Kind<?> eventKind = domainFolderToEventEntry.getValue();
					// domain folder name is assumed to be a domain ID
					final Path lastPathSegment = domainDirPath.getFileName();
					if (lastPathSegment == null)
					{
						throw new RuntimeException("Invalid Domain folder '" + domainDirPath + "': no filename");
					}

					final String domainId = lastPathSegment.toString();
					if (eventKind == ENTRY_CREATE || eventKind == ENTRY_MODIFY)
					{
						/*
						 * synchonized block makes sure no other thread is messing with the domains directory while we synchronize it to domainMap. See also
						 * method #add(Properties)
						 */
						synchronized (domainsRootDir)
						{
							final DOMAIN_DAO_CLIENT secDomain = domainMap.get(domainId);
							// Force creation if domain does not exist, else
							// reload
							if (secDomain == null)
							{
								// force creation
								LOGGER.info("Sync event '{}' on domain '{}: domain not found in memory -> loading new domain from folder '{}'", new Object[] {
										eventKind, domainId, domainDirPath });
								addDomainToMapsAfterDirectoryCreated(domainId, domainDirPath.toFile(), null);
							} else
							{
								LOGGER.info("Sync event '{}' on domain '{}: domain found in memory -> reloading from folder '{}'", new Object[] { eventKind,
										domainId, domainDirPath });
								secDomain.getDAO().reloadPDP();
							}
						}
					} else if (eventKind == ENTRY_DELETE)
					{
						// it's only removing from the map so no need to sync on the filesystem directory
						LOGGER.info("Sync event '{}' on domain '{}: deleting if exists in memory", new Object[] { eventKind, domainId, domainDirPath });
						removeDomainFromMapsAfterDirectoryDeleted(domainId);
					}
				}

				LOGGER.debug("Synchronization done.");

				domainFolderToEventMap.clear();
			} catch (Throwable e)
			{
				LOGGER.error("Error occurred during domains folder synchronization task", e);
			}
		}

		private void removeDomainFromMapsAfterDirectoryDeleted(String domainId)
		{
			final Iterator<Entry<String, String>> domainEntryIterator = domainIDsByExternalId.entrySet().iterator();
			while (domainEntryIterator.hasNext())
			{
				final Entry<String, String> domainEntry = domainEntryIterator.next();
				if (domainId.equals(domainEntry.getValue()))
				{
					domainEntryIterator.remove();
				}
			}
		}
	}

	/**
	 * Creates instance
	 * 
	 * @param domainsRoot
	 *            root directory of the configuration data of security domains, one subdirectory per domain
	 * @param domainTmpl
	 *            domain template directory; directories of new domains are created from this template
	 * @param domainsSyncIntervalSec
	 *            how often (in seconds) the synchronization of managed domains (in memory) with the domain subdirectories in the <code>domainsRoot</code>
	 *            directory (on disk) is done. If <code>domainSyncInterval</code> > 0, every <code>domainSyncInterval</code>, the managed domains (loaded in
	 *            memory) are updated if any change has been detected in the <code>domainsRoot</code> directory in this interval (since last sync). To be more
	 *            specific, <i>any change</i> here means any creation/deletion/modification of a domain folder (modification means: any file changed within the
	 *            folder). If <code>domainSyncInterval</code> &lt;= 0, synchronization is disabled.
	 * @param pdpModelHandler
	 *            PDP configuration model handler
	 * @param maxNumOfPoliciesPerDomain
	 *            max number of policies per domain, unlimited if negative.
	 * @param useRandomAddressBasedUUID
	 *            true iff a random multicast address must be used as node field of generated UUIDs (Version 1), else the MAC address of one of the network
	 *            interfaces is used. Setting this to 'true' is NOT recommended unless the host is disconnected from the network. These generated UUIDs are used
	 *            for domain IDs.
	 * @param maxNumOfVersionsPerPolicy
	 *            max number of versions per policy, unlimited if negative.
	 * @param domainDAOClientFactory
	 *            domain DAO client factory
	 * @throws IOException
	 *             I/O error occurred scanning existing domain folders in {@code domainsRoot} for loading; or if {@code domainsSyncIntervalSec > 0} and a
	 *             WatchService for watching directory changes to the domains on the filesystem could not be created
	 */
	@ConstructorProperties({ "domainsRoot", "domainTmpl", "domainsSyncIntervalSec", "pdpModelHandler", "useRandomAddressBasedUUID",
			"maxNumOfPoliciesPerDomain", "maxNumOfVersionsPerPolicy", "domainDAOClientFactory" })
	public FileBasedDomainsDAO(
			Resource domainsRoot,
			Resource domainTmpl,
			int domainsSyncIntervalSec,
			PdpModelHandler pdpModelHandler,
			boolean useRandomAddressBasedUUID,
			int maxNumOfPoliciesPerDomain,
			int maxNumOfVersionsPerPolicy,
			DomainDAOClient.Factory<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT, FileBasedDomainDAO<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT>, DOMAIN_DAO_CLIENT> domainDAOClientFactory)
			throws IOException
	{
		if (domainsRoot == null || domainTmpl == null || pdpModelHandler == null || domainDAOClientFactory == null)
		{
			throw ILLEGAL_CONSTRUCTOR_ARGS_EXCEPTION;
		}

		this.domainDAOClientFactory = domainDAOClientFactory;
		this.policyDAOClientFactory = domainDAOClientFactory.getPolicyDAOClientFactory();
		this.policyVersionDAOClientFactory = policyDAOClientFactory.getVersionDAOClientFactory();

		this.maxNumOfPoliciesPerDomain = maxNumOfPoliciesPerDomain;
		this.maxNumOfPoliciesReachedException = new TooManyPoliciesException("Max number of policies (" + maxNumOfPoliciesPerDomain
				+ ") reached for the domain");
		this.maxNumOfVersionsPerPolicy = maxNumOfVersionsPerPolicy;
		this.maxNumOfVersionsReachedException = new TooManyPoliciesException("Max number of versions (" + maxNumOfVersionsPerPolicy
				+ ") reached for the policy");

		this.uuidGen = initUUIDGenerator(useRandomAddressBasedUUID);
		this.pdpModelHandler = pdpModelHandler;

		// Validate domainsRoot arg
		if (!domainsRoot.exists())
		{
			throw new IllegalArgumentException("'domainsRoot' resource does not exist: " + domainsRoot.getDescription());
		}

		final String ioExMsg = "Cannot resolve 'domainsRoot' resource '" + domainsRoot.getDescription() + "' as a file on the file system";
		File domainsRootFile = null;
		try
		{
			domainsRootFile = domainsRoot.getFile();
		} catch (IOException e)
		{
			throw new IllegalArgumentException(ioExMsg, e);
		}

		FileBasedDAOUtils.checkFile("File defined by SecurityDomainManager parameter 'domainsRoot'", domainsRootFile, true, true);
		this.domainsRootDir = domainsRootFile.toPath();

		// Validate domainTmpl directory arg
		if (!domainTmpl.exists())
		{
			throw new IllegalArgumentException("'domainTmpl' resource does not exist: " + domainTmpl.getDescription());
		}

		final String ioExMsg2 = "Cannot resolve 'domainTmpl' resource '" + domainTmpl.getDescription() + "' as a file on the file system";
		File domainTmplFile = null;
		try
		{
			domainTmplFile = domainTmpl.getFile();
		} catch (IOException e)
		{
			throw new IllegalArgumentException(ioExMsg2, e);
		}

		FileBasedDAOUtils.checkFile("File defined by SecurityDomainManager parameter 'domainTmpl'", domainTmplFile, true, false);
		this.domainTmplDir = domainTmplFile;

		// Initialize endUserDomains and register their folders to the
		// WatchService for monitoring
		// them at the same time
		final DomainsFolderSyncTask syncTask;
		if (domainsSyncIntervalSec > 0)
		{
			// Sync enabled
			WatchService fsWatchService = null;
			try
			{
				fsWatchService = FileSystems.getDefault().newWatchService();
			} catch (IOException e)
			{
				throw new IOException("Failed to create a WatchService for watching directory changes to the domains on the filesystem", e);
			}

			if (fsWatchService == null)
			{
				throw new IOException("Failed to create a WatchService for watching directory changes to the domains on the filesystem");
			}

			this.domainsFolderWatcher = fsWatchService;
			syncTask = new DomainsFolderSyncTask();
			syncTask.addWatchedDirectory(this.domainsRootDir);
		} else
		{
			this.domainsFolderWatcher = null;
			syncTask = null;
		}

		LOGGER.debug("Looking for domain sub-directories in directory {}", domainsRootDir);
		try (final DirectoryStream<Path> dirStream = Files.newDirectoryStream(domainsRootDir))
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
					throw new RuntimeException("Invalid Domain folder '" + domainPath + "': no filename");
				}

				final String domainId = lastPathSegment.toString();
				final FileBasedDomainDAO<VERSION_DAO_CLIENT, POLICY_DAO_CLIENT> domainDAO;
				try
				{
					domainDAO = new FileBasedDomainDAOImpl(domainPath.toFile(), null);
				} catch (IllegalArgumentException e)
				{
					throw new RuntimeException("Invalid domain data for domain '" + domainId + "'", e);
				}

				final DOMAIN_DAO_CLIENT domain = domainDAOClientFactory.getInstance(domainId, domainDAO);
				domainMap.put(domainId, domain);

				if (syncTask != null)
				{
					syncTask.addWatchedDirectory(domainPath);
				}
			}
		} catch (IOException e)
		{
			throw new IOException("Failed to scan files in the domains root directory '" + domainsRootDir + "' looking for domain directories", e);
		}

		/*
		 * No error occurred, we can start new thread for watching/syncing domains safely now if sync interval > 0
		 */
		if (syncTask != null)
		{
			domainsFolderSyncTaskScheduler = Executors.newScheduledThreadPool(1);
			LOGGER.info("Scheduling periodic domains folder synchronization (initial delay={}s, period={}s)", domainsSyncIntervalSec, domainsSyncIntervalSec);
			domainsFolderSyncTaskScheduler.scheduleWithFixedDelay(syncTask, domainsSyncIntervalSec, domainsSyncIntervalSec, TimeUnit.SECONDS);
		} else
		{
			domainsFolderSyncTaskScheduler = null;
		}

		this.domainsFolderSyncIntervalSec = domainsSyncIntervalSec;
	}

	/**
	 * Stop domains folder synchronization thread (to be called by Spring when application stopped)
	 */
	public void stopDomainsSync()
	{
		if (domainsFolderSyncTaskScheduler != null)
		{
			LOGGER.info("Requesting shutdown of scheduler of periodic domains folder synchronization. Waiting {}s for pending sync task to complete...",
					domainsFolderSyncIntervalSec);
			shutdownAndAwaitTermination(domainsFolderSyncTaskScheduler);
			try
			{
				LOGGER.info("Closing WatchService used for watching domains folder", domainsFolderSyncIntervalSec);
				domainsFolderWatcher.close();
			} catch (IOException e)
			{
				LOGGER.error("Failed to close WatchService. This may cause a memory leak.", e);
			}
		}
	}

	/*
	 * Code adapted from ExecutorService javadoc
	 */
	private void shutdownAndAwaitTermination(ExecutorService pool)
	{
		pool.shutdown(); // Disable new tasks from being submitted
		try
		{
			// Wait a while for existing tasks to terminate
			if (!pool.awaitTermination(domainsFolderSyncIntervalSec, TimeUnit.SECONDS))
			{
				LOGGER.error("Scheduler wait timeout ({}s) occurred before task could terminate after shutdown request.", domainsFolderSyncIntervalSec);
				pool.shutdownNow(); // Cancel currently executing tasks
				// Wait a while for tasks to respond to being cancelled
				if (!pool.awaitTermination(domainsFolderSyncIntervalSec, TimeUnit.SECONDS))
				{
					LOGGER.error("Scheduler wait timeout ({}s) occurred before task could terminate after shudownNow request.", domainsFolderSyncIntervalSec);
				}
			}
		} catch (InterruptedException ie)
		{
			LOGGER.error("Scheduler interrupted while waiting for sync task to complete", ie);
			// (Re-)Cancel if current thread also interrupted
			pool.shutdownNow();
			// Preserve interrupt status
			Thread.currentThread().interrupt();
		}
	}

	@Override
	public DOMAIN_DAO_CLIENT getDomainDAOClient(String domainId)
	{
		if (domainId == null)
		{
			throw NULL_DOMAIN_ID_ARG_EXCEPTION;
		}

		return domainMap.get(domainId);
	}

	@Override
	public String addDomain(WritableDomainProperties props) throws IOException, IllegalArgumentException
	{
		final UUID uuid = uuidGen.generate();
		/*
		 * Encode UUID with Base64url to have shorter IDs in REST API URL paths and to be compatible with filenames on any operating system, since the resulting
		 * domain ID is used as name for the directory where all the domain's data will be stored.
		 */
		final ByteBuffer byteBuf = ByteBuffer.wrap(new byte[16]);
		byteBuf.putLong(uuid.getMostSignificantBits());
		byteBuf.putLong(uuid.getLeastSignificantBits());
		final String domainId = FileBasedDAOUtils.base64UrlEncode(byteBuf.array());
		synchronized (domainsRootDir)
		{
			// this should not happen if the UUID generator can be trusted, but
			// - hey - we never
			// know.
			if (this.domainMap.containsKey(domainId))
			{
				throw new ConcurrentModificationException(
						"Generated domain ID conflicts (is same as) ID of existing domain (flawed domain UUID generator or ID generated in different way?): ID="
								+ domainId);
			}

			final Path domainDir = this.domainsRootDir.resolve(domainId);
			final File domainDirFile = domainDir.toFile();
			if (Files.notExists(domainDir))
			{
				/*
				 * Create/initialize new domain directory from domain template directory
				 */
				FileUtils.copyDirectory(this.domainTmplDir, domainDirFile);
			}

			addDomainToMapsAfterDirectoryCreated(domainId, domainDirFile, props);
		}

		return domainId;
	}

	@Override
	public Set<String> getDomainIDs(String externalId)
	{
		if (externalId == null)
		{
			return Collections.unmodifiableSet(domainMap.keySet());
		}

		final String domainId = domainIDsByExternalId.get(externalId);
		return domainId == null ? Collections.<String> emptySet() : Collections.<String> singleton(domainId);
	}

	@Override
	public boolean containsDomain(String domainId)
	{
		if (domainId == null)
		{
			throw NULL_DOMAIN_ID_ARG_EXCEPTION;
		}

		return domainMap.containsKey(domainId);
	}

}
