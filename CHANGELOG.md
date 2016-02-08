# Change log
All notable changes to this project are documented in this file following the [Keep a CHANGELOG](http://keepachangelog.com) conventions.

## Unreleased
### Changed
- Version of implemented PAP API (dependency 'core-pap-api'), i.e. 4.0.0, in particular:
    - PolicyVersion type used for policy versions (instead of String)
    - Implemented getLatestPolicyVersion(policyId) to get latest version of a given policy

### Added
- Enabled/disabled automatic removal of oldest versions if maximum allowed number of versions for a policy is reached
- Caching of policy versions to help get latest policy version
- Use of new PdpImpl#getStaticRootAndRefPolicies() to check policies required by PDP before removing any policy (version)

## 3.6.1
### Fixed
- Error handling when removing a policy and setting policy with invalid refs as root policy

## 3.6.0
### Added
- Initial release on Github



