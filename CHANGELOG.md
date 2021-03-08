# Change log
All notable changes to this project are documented in this file following the [Keep a CHANGELOG](http://keepachangelog.com) conventions.

Issues reported on [GitHub](https://github.com/authzforce/core/issues) are referenced in the form of `[GH-N]`, where N is the issue number. Issues reported on [OW2](https://jira.ow2.org/browse/AUTHZFORCE/) are mentioned in the form of `[OW2-N]`, where N is the issue number.


## 13.0.0
### Changed
- Upgraded parent project to 8.0.0: full switch to Java 11 support (Java 8 no longer supported)
- Upgraded authzforce-ce-core-pdp-* dependencies to 17.1.0:
  - Upgraded JAXB (Jakarta XML Bining) to v2.3.3
  - Upgraded authzforce-ce-core-pdp-api to v18.0.1 (fixes issue authzforce/server#62 : same XML namespace prefix cannot be reused in more than one namespace declaration when parsing XACML documents with `XmlUtils$SAXBasedXmlnsFilteringParser`)
  - Upgraded authzforce-ce-xacml-json-model: 3.0.1 (fixed issue with method `XacmlJsonUtils#canonicalizeResponse()` when comparing similar XACML/JSON responses, linked to https://github.com/stleary/JSON-java/issues/589 )
- upgraded authzforce-ce-core-pap-api to 11.0.0

### Added
- XACML JSON Profile feature: support for JSON Objects in XACML/JSON Attribute Values (linked to issue authzforce/server#61 ), allowing for complex structures (JSON objects) as data types

### Fixed
- Fixed CVE on jackson-databind -> v2.9.10.8


## 12.0.0
### Changed
- Upgraded parent project: 7.6.1
- Upgraded dependency
	- authzforce-ce-core-pdp-engine: 16.0.0: simplified Policy Provider architecture
		- PDP configuration schema changes (XML Schema 'pdp.xsd') v7.0.0 (more info in [migration guide](https://github.com/authzforce/core/blob/develop/MIGRATION.md) )
			- Simplified namespace (removed minor version) to `http://authzforce.github.io/core/xmlns/pdp/7`
			- Replaced 'refPolicyProvider' and 'rootPolicyProvider' XML elements with 'policyProvider' and 'rootPolicyRef' (optional). If 'rootPolicyRef' undefined, the new `PolicyProvider#getCandidateRootPolicy()` method is called to determine a possible root policy.
		- Policy Provider API changes
	- java-uuid-generator: 4.0.1
	- authzforce-ce-core-pap-api: 10.1.0
- Changed namespace of extension XML schema: `http://authzforce.github.io/pap-dao-flat-file/xmlns/pdp-ext/4`
- Renamed XML type 'StaticFlatFileDAORefPolicyProvider' to 'StaticFlatFileDaoPolicyProviderDescriptor' in extension XML schema
- Renamed class FlatFileDAORefPolicyProviderModule to FlatFileDaoPolicyProvider
- FlatFileDaoPolicyProvider implements new PolicyProvider API (class BaseStaticPolicyProvider and class CloseablePolicyProvider.Factory)
- FlatFileBasedDomainsDao: support new PDP configuration schema changes


## Added
- Support for **Multiple Decision Profile when used with XACML/JSON Profile** (authzforce-ce-core-pdp-engine upgrade) 

## Fixed
- Issue (related to [authzforce-ce-server issue](https://github.com/authzforce/server/issues/46) ) in `addPolicy()` with bad PolicySets being added and saved to filesystem despite the IllegalArgumentException (or other exception) raised. Any PolicySet input to addPolicy() is now fully validated by attempting to load it as root policy in a PDP before saving it.


## 11.0.0
### Changed
- Major PAP API (extended Java interface) version upgrade: authzforce-ce-core-pap-api v10.0.0

### Added
- Systematic validation in implementation of `DomainDao#addPolicy(PolicySet)`: all input policies are validated, for safety and better troubleshooting, i.e. detect errors as early as possible before using any policy. Policies are validated by trying to load the PDP configuration with the input policy as root policy.


## 10.1.0
### Added
- `EnvironmentProperties#replacePlaceholders()` method now supports system properties and environment variables; and a default value (separated from the property name by '!') if the property is undefined. Therefore, PDP extensions such as Attribute and Policy Providers can accept placeholders for system properties and environment variables in their string configuration parameters (as part of PDP configuration) and perform placeholder replacements with their factory method's input `EnvironmentProperties`. In particular, `policyLocation` elements in PDP's Policy Providers configuration now supports (not only `PARENT_DIR` property but also) system properties and environment variables (enclosed between `${...}`) with default value if property/variable undefined.

### Fixed
- CVE affecting Spring 4.3.18: upgraded dependencies to depend on
4.3.20:
	- authzforce-ce-parent: 7.5.1
	- authzforce-ce-core: 13.3.1
		- authzforce-ce-core-pdp-api: 15.3.0
			- Guava: 24.1.1-jre
	- authzforce-ce-xacml-json-model: 2.1.1
- Upgraded java-uuid-generator: 3.1.5


## 10.0.0
### Changed
- Parent project (authzforce-ce-parent) version: 7.3.0
- Dependency versions:
	- authzfore-ce-core: 13.2.0
		- authzforce-ce-xacml-json-model: 2.0.0
                - authzforce-ce-core-pdp-api: 15.2.0
                - Spring: 4.3.14
        - authzforce-ce-core-pap-api: 9.2.0
- License headers: copyright extended to year 2018
- `FlatFileDAORefPolicyProviderModule` class: changed to comply with new contract of superclass `BaseStaticRefPolicyProvider` from core-pdp-api (parameter type `VersionPatterns` replaced with `PolicyVersionPatterns`)


## 9.1.0
### Changed
- Parent project (authzforce-ce-parent) version: 7.0.0 -> 7.1.0
- Dependency versions: 
	- authzforce-ce-core: 10.0.0 -> 10.1.0:
		- authzforce-ce-xacml-json-model: 1.0.0 -> 1.1.0
			- org.everit.json.schema: 1.6.0 -> 1.6.1
			- guava: 21.0 -> 22.0
			- json: 20170516 -> 20171018
		- authzforce-ce-core-pdp-api: 12.0.0 -> 12.1.0
	- authzforce-ce-core-pap-api: 9.0.0 -> 9.1.0

### Added
- Uniqueness check on domains' externalId property (not two domains may have the same), before allowing to create new domain or changing a domain's externalId


## 9.0.0
### Changed
- Changed parent project (authzforce-ce-parent) version: 5.1.0 -> 7.0.0
  - Spring: 4.3.6 -> 4.3.12
- Changed authzforce-ce-core-pap-api version: 6.4.0 -> 9.0.0
  - authzforce-ce-core-pdp-api: 9.1.0 -> 12.0.0
	- More optimal implementation of XACML integer values: 3 possible GenericInteger interface implementations depending on maximum (size) (ArbitrarilyBigInteger for java BigIntegers, MediumInteger for java Integers, and LongInteger for java Longs), with value caching (like Java Integer/Long). This optimizes memory usage / CPU computation when dealing with XACML integers small enough to fit in Java Integers/Longs.
    - Changed Java class naming conventions regarding acronyms (only first letter should be uppercase, see also
https://google.github.io/styleguide/javaguide.html#s5.3-camel-case)
    - Each domain now has 2 PDP engines for both XACML/XML and XACML/JSON input/output if JSON Profile enabled
- Changed authzforce-ce-core-pdp-engine: 8.0.0 -> 10.0.0
  - Changed PDP configuration XSD: 5.0.0 -> 6.0.0:
	- Replaced attributes `requestFilter` and `resultFilter` with element `ioProcChain` of new type `InOutProcChain` defining a pair of request preprocessor (ex-requestFilter) and result postprocessor (ex-resultFilter)
	- (not visible via API) Replaced attribute `badRequestStatusDetailLevel` with `clientRequestErrorVerbosityLevel`
	- (not visible via API) Added `maxIntegerValue` attribute allowing to define the expected max integer value to be handled by the PDP engine during evaluation, based on which the engine selects the best Java representation among several (BigInteger, Long, Integer) for memory and CPU usage optimization
- Changed PDP feature identifiers (in pdpProperties): *:request-filter:* -> *:request-preproc:*; *:result-filter:* -> *:result-postproc:*

### Added
- Possibility of defining two pairs of request/result processors, 1 for XACML/XML and 1 for XACML/JSON input/output
- Added dependency authzforce-ce-core-pdp-io-xacml-json for JSON Profile support in domain's PDP.


## 8.1.0
### Changed
- Version of parent project (authzforce-ce-parent): 5.1.0:
	- Project URL: https://tuleap.ow2.org/projects/authzforce -> https://authzforce.ow2.org
	- GIT repository URL base: https://tuleap.ow2.org/plugins/git/authzforce -> https://gitlab.ow2.org/authzforce
- Version of dependency authzforce-ce-core-pap-api: 6.4.0
- Dependency authzforce-ce-core replaced with authzforce-ce-core-pdp-engine (authzforce-ce-core is now a multi-module project made of the core module `pdp-engine` and test utilities module `pdp-testutils`) with version 8.0.0


## 8.0.0
### Changed
- Version of parent project (authzforce-ce-parent): 5.0.0
- Version of dependency authzforce-ce-core-pap-api: 6.3.0 -> API changes (non-backward compatible): 
	- Return type of DomainDAO#getPDP() changed to PDPEngine (instead of Pdp)
	- PDP extension interfaces changed:  DecisionCache, DecisionResultFilter
- Version of dependency authzforce-ce-core: 7.1.0
- Version of dependencies SLF4J: 1.7.22; Spring: 4.3.6; Guava: 21.0

### Fixed
- [OW2-25] NullPointerException when parsing Apply expressions using invalid/unsupported Function ID. This is the final fix addressing higher-order functions. Initial fix in v7.0.0 only addressed first-order ones.


## 7.0.0
### Added
* enablePdpOnly: this `FlatFileBasedDomainsDAO` constructor argument disables all PAP/"admin" features and supports only PDP decision requests/responses. 
* Extension mechanism to switch HashMap/HashSet implementation; default implementation is based on native JRE and Guava.
* From dependency authzforce-ce-core 6.1.0:
	* Validation of 'n' argument (minimum of *true* arguments) of XACML 'n-of' function if this is constant (must be a positive integer not greater than the number of remaining arguments)
	* Validation of second and third arguments of XACML substring function if these are constants (arg1 >= 0 && (arg2 == -1 || arg2 >= arg1))

### Changed
* Maven parent project version: 3.4.0 -> 4.1.1:
	* **Java version: 1.7 -> 1.8**
	* Guava dependency version: 18.0 -> 20.0
	* Spring 4.3.4 -> 4.3.5, 
    * Saxon-HE 9.7.0-11 -> 9.7.0-14
    * com.sun.mail:javax.mail v1.5.4 -> com.sun.mail:mailapi v1.5.6
* Dependency authzforce-ce-core-pap-api 5.3.0 -> 6.2.0: new interface method DomainDAO#isPAPEnabled() to indicate whether the DAO supports PAP features
* Dependency authzforce-ce-core 5.0.2 -> 6.1.0, with following change:
	- Behavior of *unordered* rule combining algorithms (deny-overrides, permit-overrides, deny-unless-permit and permit-unless deny), i.e. for which the order of evaluation may be different from the order of declaration: child elements are re-ordered for more efficiency (e.g. Deny rules evaluated first in case of deny-overrides algorithm), therefore the algorithm implementation - the order of evaluation in particular - now differs from ordered-* variants.
* Replaced Guava base64URL encoder/decoder with Java 8 native (Base64 class)

### Removed
* Dependency on Koloboke, replaced by extension mechanism mentioned in *Added* section that would allow to switch from the default HashMap/HashSet implementation to Koloboke-based.

### Fixed
* From dependency authzforce-ce-core 6.0.0:
	* [OW2-23] enforcement of RuleId/PolicyId/PolicySetId uniqueness:
		* PolicyId (resp. PolicySetId) should be unique across all policies loaded by PDP so that PolicyIdReferences (resp. PolicySetIdReferences) in Responses' PolicyIdentifierList are absolute references to applicable policies (no ambiguity).
 		* [RuleId should be unique within a policy](https://lists.oasis-open.org/archives/xacml/201310/msg00025.html) -> A rule is globally uniquely identified by the parent PolicyId and the RuleId.
	* [OW2-25] NullPointerException when parsing Apply expressions using invalid/unsupported Function ID. Partial fix for first-order functions only; see release 8.0.0 for final fix.
* Security issues reported by Find Security Bugs plugin


## 6.1.0
### Fixed
- Other issues reported by Codacy

### Changed
- Parent project version: authzforce-ce-parent: 3.4.0
- Dependency version (PAP API): authzforce-ce-core-pap-api: 5.3.0
- Dependency version (PDP core engine): authzforce-ce-core: 5.0.2, with the following changes:
  - Supported PDP XML configuration (file 'pdp.xml') schema namespace: http://authzforce.github.io/core/xmlns/pdp/5.0 (previous namespace: http://authzforce.github.io/core/xmlns/pdp/3.6).
  - Fixed issue #22 (OW2): When handling the same XACML Request twice in the same JVM with the root PolicySet using deny-unless-permit algorithm over a Policy returning simple Deny (no status/obligation/advice) and a Policy returning Permit/Deny with obligations/advice, the obligation is duplicated in the final result at the second time this situation occurs. 
  - Fixed XACML StatusCode XML serialization/marshalling error when Missing Attribute info that is no valid anyURI is returned by PDP in a Indeterminate Result
  - Fixed memory management issue: native RootPolicyProvider modules keeping a reference to static refPolicyProvider, even after policies have been resolved statically at initialization time, preventing garbage collection and memory saving.
  - Interpretation of XACML Request flag ReturnPolicyId=true, considering a policy "applicable" if and only if the decision is not NotApplicable and if it is not a root policy, the same goes for the enclosing policy. See also the discussion on the xacml-comment mailing list: https://lists.oasis-open.org/archives/xacml-comment/201605/msg00004.html
  - AttributeProvider module API: new environmentProperties parameter in factories, allowing module configurations to use global Environment properties like PARENT_DIR variable
  - 'functionSet' element no longer supported in PDP XML configuration file 'pdp.xml'
  - New PDP configuration parameters supported in 'pdp.xml' file:  
    - 'standardEnvAttributeSource' (enum) sets the source for the Standard Current Time Environment Attribute values (current-date, current-time, current-dateTime): PDP_ONLY, REQUEST_ELSE_PDP, REQUEST_ONLY
    - 'badRequestStatusDetailLevel' (positive integer) sets the level of detail of the error message in StatusDetail returned in Indeterminate Results in case of bad Requests

### Added
- New methods in FlatFileDAOUtils class:
	- getPolicyVersions(Path): to get policy versions from a policy directory
	- Entry<PolicyVersion, Path> getLatestPolicyVersion(Path) to get latest version from a policy directory with path to corresponding policy file
	- PolicySet loadPolicy(Path) to load a JAXB policy from file


## 6.0.0
### Changed
- Dependency authzforce-ce-core version to 4.0.0, resulting in changes of IDs of features of type `urn:ow2:authzforce:feature-type:pdp:request-filter`:
	- `urn:ow2:authzforce:xacml:request-filter:default-lax` changed to `urn:ow2:authzforce:feature:pdp:request-filter:default-lax`;
	- `urn:ow2:authzforce:xacml:request-filter:default-strict` changed to `urn:ow2:authzforce:feature:pdp:request-filter:default-strict`;
	- `urn:ow2:authzforce:xacml:request-filter:multiple:repeated-attribute-categories-strict` changed to `urn:ow2:authzforce:feature:pdp:request-filter:multiple:repeated-attribute-categories-strict`;
	- `urn:ow2:authzforce:xacml:request-filter:multiple:repeated-attribute-categories-lax` changed to `urn:ow2:authzforce:feature:pdp:request-filter:multiple:repeated-attribute-categories-lax`.
- Dependency authzforce-ce-core-pap-api version to 5.2.0.

### Fixed
- License headers (current year)


## 5.1.0
### Added
- Support for authzforce-ce-core-pap-api v5.1.0: Management of PDP features (extensions), i.e. listing, get status, activation/de-activation: custom XACML datatypes, custom functions, custom policy/rule combining algorithms, custom XACML Request filter, custom XACML Result filter.


## 5.0.2
### Fixed
- authzforce-ce-core dependency upgraded to v3.8.3 to fix hard arbitrary limitation on maxVarRefDepth and maxPolicyRefDepth attributes: removed any max value (used to be 100 for both).


## 5.0.1
### Fixed
- Version of dependency authzforce-ce-core upgraded to v3.8.2 fixing possible memory leak spotted by Tomcat because of using ThreadLocal that is never cleaned (SAXON 9.6 - StandardURIChecker/LRUCache)


## 5.0.0
### Changed 
- Implemented PAP DAO API (authzforce-ce-core-pap-api): v5.0.0


## 4.0.0
### Added
- Option for policy version rolling (automatic removal of oldest versions if maximum allowed number of versions for a policy is reached)
- Use of new PdpImpl#getStaticApplicablePolicies() to check policies required by PDP before removing any policy (version)
- Manual synchronization of domains:
  - FlatFileBasedDomainsDAO#getDomainIDs() forces re-synchronization of all domains
  - FlatFileBasedDomainDAO#get*() methods force re-synchronization of the domain to make sure the returned data is up-to-date
  - FlatFileBasedDomainDAO#removeDomain() removes the domain from cache even if the domain directory is already deleted on disk

### Changed
- Version of supported PAP core API (authzforce-ce-core-pap-api): 4.0.0, i.e. new features:
	- Get latest version of given policy in a domain
	- Get new PDP-specific properties of a domain: enabled policies (applicable by the PDP), last modified time (last time PDP was instantiated, in particular when synced with the domain data directory)
	- Get/enable PDP feature 'Multiple Decision Profile' for a domain
	- Get/set new PRP-specific properties of a domain: max policy count per domain, max version count per policy,  version rolling (enable automatic rolling of versions when max version count per policy is reached)
	- PolicyVersion class used for policy versions (instead of String)
- Version of backend PDP core implementation (authzforce-ce-core): 3.8.0
- Namespace of XML schema of domain properties changed from "http://authzforce.github.io/pap-dao-file/xmlns/properties/3.6" to "http://authzforce.github.io/pap-dao-flat-file/xmlns/properties/3.6"
- Namespace of XML schema of refPolicyProvider (PDP extension) changed from "http://authzforce.github.io/pap-dao-file/xmlns/pdp-ext/3.6" to "http://authzforce.github.io/pap-dao-flat-file/xmlns/pdp-ext/3.6"
- XML type of the refPolicyProvider (in previously mentioned schema) changed from 'StaticFileBasedDAORefPolicyProvider' to 'StaticFlatFileDAORefPolicyProvider'
- Strategy for synchronizing cached domain's PDP and externalId-to-domain mapping with configuration files: no longer using Java WatchService, but each domain has a specific thread polling files in the domain directory's and checking their lastModifiedTime attribute for change:
  - If a given domain ID is requested and no matching domain in cache, but a matching domain directory is found, the domain is automatically synced to cache and the synchronizing thread created;
  - If the domain's directory found missing by the synchronizing thread, the thread deletes the domain from cache.
  - If any change to properties.xml (domain description, externalId) detected, externalId updated in cache
  - If any change to pdp.xml or the file of any policy used by the PDP, the PDP is reloaded.


## 3.6.1
### Fixed
- Error handling when removing a policy and setting policy with invalid refs as root policy


## 3.6.0
### Added
- Initial release on Github



