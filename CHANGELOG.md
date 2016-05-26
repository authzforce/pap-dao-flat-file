# Change log
All notable changes to this project are documented in this file following the [Keep a CHANGELOG](http://keepachangelog.com) conventions.


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



