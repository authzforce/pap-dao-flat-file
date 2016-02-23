# Change log
All notable changes to this project are documented in this file following the [Keep a CHANGELOG](http://keepachangelog.com) conventions.

## Unreleased
### Added
- Option for automatic removal of oldest versions if maximum allowed number of versions for a policy is reached
- Use of new PdpImpl#getStaticRootAndRefPolicies() to check policies required by PDP before removing any policy (version)
- Manual synchronization of domains:
  - FlatFileBasedDomainsDAO#getDomainIDs() forces re-synchronization of all domains
  - FlatFileBasedDomainDAO#get*() methods force re-synchronization of the domain to make sure the returned data is up-to-date

### Changed
- Strategy for synchronizing cached domain's PDP and externalId-to-domain mapping with configuration files: no longer using Java WatchService, but each domain has a specific thread polling files in the domain directory's and checking their lastModifiedTime attribute for change:
  - If a given domain ID is requested and no maching domain in cache, but a matching domain directory is found, the domain is automatically synced to cache and the synchronizing thread created;
  - If the domain's directory found missing by the synchronizing thread, the thread deletes the domain from cache.
  - If any change to properties.xml (domain description, externalId) detected, externalId updated in cache
  - If any change to pdp.xml or the file of any policy used by the PDP, the PDP is reloaded.
- Version of implemented PAP API (dependency 'core-pap-api'), i.e. 4.0.0, in particular:
    - PolicyVersion type used for policy versions (instead of String)
    - Implemented getLatestPolicyVersion(policyId) to get latest version of a given policy


## 3.6.1
### Fixed
- Error handling when removing a policy and setting policy with invalid refs as root policy

## 3.6.0
### Added
- Initial release on Github



