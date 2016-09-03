# Change log
All notable changes to this project are documented in this file following the [Keep a CHANGELOG](http://keepachangelog.com) conventions.

# Unreleased
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



