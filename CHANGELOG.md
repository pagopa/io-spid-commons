# @pagopa/io-spid-commons

## 15.0.0

### Major Changes

- [#174](https://github.com/pagopa/io-spid-commons/pull/174) [`1894a9a`](https://github.com/pagopa/io-spid-commons/commit/1894a9a1a0716c7a4f4a94bf4dc61429a756cdfe) Thanks [@arcogabbo](https://github.com/arcogabbo)! - Upgrade to Node 22

## 14.0.1

### Patch Changes

- xml-crypto bump [#168](https://github.com/pagopa/io-spid-commons/pull/168)

## 14.0.0

### Major Changes

- [#IOPID-2514] upgrade to node20 [#166](https://github.com/pagopa/io-spid-commons/pull/166)

## 13.5.1

### Patch Changes

- [#IOPID-1994] Move redis to peerDependency [#164](https://github.com/pagopa/io-spid-commons/pull/164)

## 13.5.0

### Minor Changes

- [#IOPID-1845] Move io-ts and fp-ts in peerDependency [#163](https://github.com/pagopa/io-spid-commons/pull/163)

## 13.4.0

### Minor Changes

- [#IOPID-1612, #IOPID-1513] SAMLResponse missing errorMessage [#156](https://github.com/pagopa/io-spid-commons/pull/156)

## 13.3.0

### Minor Changes

- [#IOPID-1156] Include additional params in doneCb, if any [#153](https://github.com/pagopa/io-spid-commons/pull/153)

## 13.2.2

### Patch Changes

- [#IOPID-972] Add Intesi Group IdP in whitelist [#151](https://github.com/pagopa/io-spid-commons/pull/151)

## 13.2.1

### Patch Changes

- [#IOPID-437] Conversion EntityID commercial IdP names [#150](https://github.com/pagopa/io-spid-commons/pull/150)

## 13.2.0

### Minor Changes

- [#IOPID-416] Add request to acs callback [#149](https://github.com/pagopa/io-spid-commons/pull/149)

## 13.1.0

### Minor Changes

- [#IOPID-328] Store extra parameter on login step [#148](https://github.com/pagopa/io-spid-commons/pull/148)

## 13.0.1

### Patch Changes

- [#IOPID-256] upgrade xmldom [#147](https://github.com/pagopa/io-spid-commons/pull/147)

## 13.0.0

### Major Changes

- [#IOCIT-260] Upgrade redis Client to v4.5.1 [#133](https://github.com/pagopa/io-spid-commons/pull/133)

## 12.0.1

### Patch Changes

- [#IOPID-190] Fix xmldom types for `DOMParser.parseFromString` [#145](https://github.com/pagopa/io-spid-commons/pull/145)

## 12.0.0

### Major Changes

- Upgrade dependencies: io-ts fp-ts eslint [#144](https://github.com/pagopa/io-spid-commons/pull/144)

## 11.1.0

### Minor Changes

- [#IOPID-143] remove intesaid from idp list [#142](https://github.com/pagopa/io-spid-commons/pull/142)

## 11.0.0

### Major Changes

- Update node version in deploy pipeline [#143](https://github.com/pagopa/io-spid-commons/pull/143)
- [IOCOM-181] Migrate node 18 [#141](https://github.com/pagopa/io-spid-commons/pull/141)

## 10.1.1

### Patch Changes

- [#IOPID-130] Add support for Infocamere SPID IDP [#139](https://github.com/pagopa/io-spid-commons/pull/139)

## 10.1.0

### Minor Changes

- Add EHTID IDP [#136](https://github.com/pagopa/io-spid-commons/pull/136)

## 10.0.0

### Major Changes

- Remove Lollipop Allowed user Agent Header Name [#137](https://github.com/pagopa/io-spid-commons/pull/137)

## 9.2.0

### Minor Changes

- [#IOCIT-240] Add Semver check to Lollipop User Agent [#132](https://github.com/pagopa/io-spid-commons/pull/132)

## 9.1.0

### Minor Changes

- Internal changes.

## 9.0.0

### Major Changes

- [#IOCIT-240] Add support for Lollipop flow [#129](https://github.com/pagopa/io-spid-commons/pull/129)

## 8.1.2

### Patch Changes

- [#IOCIT-161] Add new config for test CIE metadata [#128](https://github.com/pagopa/io-spid-commons/pull/128)

## 8.1.1

### Patch Changes

- [#IOCIT-119] timing deltas logging [#121](https://github.com/pagopa/io-spid-commons/pull/121)
- [#IOCIT-118] make prevalidate errors more readable [#119](https://github.com/pagopa/io-spid-commons/pull/119)
- added chore section to PR_TEMPLATE file [#120](https://github.com/pagopa/io-spid-commons/pull/120)

## 8.1.0

### Minor Changes

- chore(deps): bump node-fetch from 2.6.1 to 2.6.7 [#108](https://github.com/pagopa/io-spid-commons/pull/108)
- chore(deps): bump async from 3.2.1 to 3.2.4 [#112](https://github.com/pagopa/io-spid-commons/pull/112)
- Add the new TeamSystem ID IDP [#118](https://github.com/pagopa/io-spid-commons/pull/118)

## 8.0.0

### Major Changes

- Fixed bad parameter passed to SpidStrategy constructor [#109](https://github.com/pagopa/io-spid-commons/pull/109)
- Added PR template file [#116](https://github.com/pagopa/io-spid-commons/pull/116)
- [#IOCIT-56] fix: updated redis types library to let hub-spid-login build correctly [#115](https://github.com/pagopa/io-spid-commons/pull/115)
- fix: package.json & yarn.lock to reduce vulnerabilities [#114](https://github.com/pagopa/io-spid-commons/pull/114)

## 7.0.3

### Patch Changes

- [#IC-501] migrated tslint to eslint [#110](https://github.com/pagopa/io-spid-commons/pull/110)

## 7.0.2

### Patch Changes

- [#IC-451] Fix preproduction CIE Metadata and entityId configuration [#107](https://github.com/pagopa/io-spid-commons/pull/107)

## 7.0.1

### Patch Changes

- chore(deps): bump node-forge from 0.10.0 to 1.0.0 [#97](https://github.com/pagopa/io-spid-commons/pull/97)

## 7.0.0

### Major Changes

- [#IP-339] Migrate fp-ts version from 1.x to 2.x [#91](https://github.com/pagopa/io-spid-commons/pull/91)
- [#174991105] Upgrade passport-saml dependency to v1.3.5 [#60](https://github.com/pagopa/io-spid-commons/pull/60)
- chore(deps): bump node-forge from 0.9.1 to 0.10.0 [#48](https://github.com/pagopa/io-spid-commons/pull/48)
- chore(deps): bump xmldom from 0.1.31 to 0.6.0 [#85](https://github.com/pagopa/io-spid-commons/pull/85)

## 6.5.1

### Patch Changes

- [#IP-359] Update Node to 14.16.0 [#88](https://github.com/pagopa/io-spid-commons/pull/88)

## 6.5.0

### Minor Changes

- Reverse Order of children in Extensions [#83](https://github.com/pagopa/io-spid-commons/pull/83)

## 6.4.0

### Minor Changes

- Enable Avviso SPID n°19 only with public full operator [#81](https://github.com/pagopa/io-spid-commons/pull/81)

## 6.3.0

### Minor Changes

- Fix required attributes value from config [#75](https://github.com/pagopa/io-spid-commons/pull/75)
- improve error logging + tests refactor [#79](https://github.com/pagopa/io-spid-commons/pull/79)

## 6.2.0

### Minor Changes

- Add transform check + tests [#76](https://github.com/pagopa/io-spid-commons/pull/76)

## 6.1.0

### Minor Changes

- Add missing files in npm bundle [#69](https://github.com/pagopa/io-spid-commons/pull/69)

## 6.0.3

### Patch Changes

- Internal changes.

## 6.0.2

### Patch Changes

- Internal changes.

## 6.0.1

### Patch Changes

- Internal changes.

## 6.0.0

### Major Changes

- chore(deps): bump ini from 1.3.5 to 1.3.8 [#67](https://github.com/pagopa/io-spid-commons/pull/67)
- [#176614756] remove github registry [#68](https://github.com/pagopa/io-spid-commons/pull/68)
- chore: remove executable bit from users.json [#64](https://github.com/pagopa/io-spid-commons/pull/64)
- [#176013578] refactor pipeline [#63](https://github.com/pagopa/io-spid-commons/pull/63)
- fix: make the example app wait for spid-testenv2 [#62](https://github.com/pagopa/io-spid-commons/pull/62)

## 5.0.0

### Major Changes

- [#173792786] Disable auth level SpidL1 [#41](https://github.com/pagopa/io-spid-commons/pull/41)

## 4.10.0

### Minor Changes

- [#175292372] Remove request-ip library [#58](https://github.com/pagopa/io-spid-commons/pull/58)

## 4.9.0

### Minor Changes

- [#175499507] Prevalidate HMAC on Assertions too [#55](https://github.com/pagopa/io-spid-commons/pull/55)

## 4.8.0

### Minor Changes

- [#175499507] Prevalidate with HMAC to fail [#54](https://github.com/pagopa/io-spid-commons/pull/54)

## 4.7.0

### Minor Changes

- [#174710289] EncryptedAssertion element forbidden [#50](https://github.com/pagopa/io-spid-commons/pull/50)

## 4.6.0

### Minor Changes

- Internal changes.

## 4.5.0

### Minor Changes

- [#174710289] Better SAML Response validation [#49](https://github.com/pagopa/io-spid-commons/pull/49)
- Downgrades danger to ^7.0.0 [#40](https://github.com/pagopa/io-spid-commons/pull/40)

## 4.4.0

### Minor Changes

- add Forbidden Unauthorized on acs [#38](https://github.com/pagopa/io-spid-commons/pull/38)

## 4.3.1

### Patch Changes

- [#172754149] avoid to log SPID request in application insights [#37](https://github.com/pagopa/io-spid-commons/pull/37)

## 4.3.0

### Minor Changes

- [#172408462] Log redirect url on spid login error [#36](https://github.com/pagopa/io-spid-commons/pull/36)

## 4.2.0

### Minor Changes

- [#172408462] try fix SPID login on invalid StatusCode [#35](https://github.com/pagopa/io-spid-commons/pull/35)

## 4.1.0

### Minor Changes

- [#172038263] Middlewares exception handling [#34](https://github.com/pagopa/io-spid-commons/pull/34)

## 4.0.0

### Major Changes

- [#172067300] avoid to log request with no response (callback) [#33](https://github.com/pagopa/io-spid-commons/pull/33)
- Bump mixin-deep from 1.3.1 to 1.3.2 [#10](https://github.com/pagopa/io-spid-commons/pull/10)
- Bump acorn from 5.7.3 to 5.7.4 [#28](https://github.com/pagopa/io-spid-commons/pull/28)

## 3.3.3

### Patch Changes

- Internal changes.

## 3.3.2

### Patch Changes

- [#158818736] fix: base64 encoded string to XML inside callback [#32](https://github.com/pagopa/io-spid-commons/pull/32)

## 3.3.1

### Patch Changes

- Internal changes.

## 3.3.0

### Minor Changes

- [#158818736] Add callback to intercept SAML requests and responses [#30](https://github.com/pagopa/io-spid-commons/pull/30)
- [#171665361] add azure pipeline [#31](https://github.com/pagopa/io-spid-commons/pull/31)

## 3.2.0

### Minor Changes

- [#171800318] preValidate with acceptedClockSkewMs [#29](https://github.com/pagopa/io-spid-commons/pull/29)

## 3.1.1

### Patch Changes

- Internal changes.

## 3.1.0

### Minor Changes

- [#171800318] NotBefore, IssueInstant and NotOnOrAfter check only on strict validation [#27](https://github.com/pagopa/io-spid-commons/pull/27)

## 3.0.0

### Major Changes

- [#171706038] Manual idps metadata update [#26](https://github.com/pagopa/io-spid-commons/pull/26)

## 2.9.1

### Patch Changes

- [#171705742] Fix npm binary path [#25](https://github.com/pagopa/io-spid-commons/pull/25)

## 2.9.0

### Minor Changes

- [#170765582] Selective update IDPS metadata [#24](https://github.com/pagopa/io-spid-commons/pull/24)

## 2.8.0

### Minor Changes

- [#171642423] Fetch testenv2 metadata [#23](https://github.com/pagopa/io-spid-commons/pull/23)

## 2.7.0

### Minor Changes

- [#171550422] fix metadata parsing [#22](https://github.com/pagopa/io-spid-commons/pull/22)

## 2.6.0

### Minor Changes

- [#171550422] Parsing CIE metadata for IDP options [#21](https://github.com/pagopa/io-spid-commons/pull/21)

## 2.5.0

### Minor Changes

- [#171311847] preValidate use optional additionalParams for any idps [#20](https://github.com/pagopa/io-spid-commons/pull/20)
- [#154357300] Add Unit Tests [#17](https://github.com/pagopa/io-spid-commons/pull/17)
- [#171474957] fix spid strategy thread safety [#19](https://github.com/pagopa/io-spid-commons/pull/19)
- [#171467326] Fix minimum level and Response issuer format validation rules [#18](https://github.com/pagopa/io-spid-commons/pull/18)

## 2.4.0

### Minor Changes

- [#170332978] Validate Assertion signature [#15](https://github.com/pagopa/io-spid-commons/pull/15)

## 2.3.1

### Patch Changes

- Internal changes.

## 2.3.0

### Minor Changes

- Internal changes.

## 2.2.1

### Patch Changes

- Internal changes.

## 2.2.0

### Minor Changes

- chore: refactoring [#14](https://github.com/pagopa/io-spid-commons/pull/14)

## 2.1.2

### Patch Changes

- Internal changes.

## 2.1.1

### Patch Changes

- Internal changes.

## 2.1.0

### Minor Changes

- Small fixes [#13](https://github.com/pagopa/io-spid-commons/pull/13)
- small fixes [#2](https://github.com/pagopa/io-spid-commons/pull/2)
- Update response validation [#1](https://github.com/pagopa/io-spid-commons/pull/1)

## 1.1.0

### Minor Changes

- [#170333051] chore: add relase it [#11](https://github.com/pagopa/io-spid-commons/pull/11)
- [#170334278] Add spid validator IdP [#8](https://github.com/pagopa/io-spid-commons/pull/8)
- [#168693658] Add support for auth routes (assertConsumer and slo) [#7](https://github.com/pagopa/io-spid-commons/pull/7)

## 0.0.3

### Patch Changes

- [#167976925] Add and export getAuthnContextFromResponse method [#6](https://github.com/pagopa/io-spid-commons/pull/6)

## 0.0.2

### Patch Changes

- [#167976925] Fix getErrorCodeFromResponse method export in dist folder [#5](https://github.com/pagopa/io-spid-commons/pull/5)
- [#167976925] Add and export getErrorCodeFromResponse method [#4](https://github.com/pagopa/io-spid-commons/pull/4)
- [#167976925] Export SpidLevel type definitions [#3](https://github.com/pagopa/io-spid-commons/pull/3)
- [#167976925] First migration for spid login classes and utils [#1](https://github.com/pagopa/io-spid-commons/pull/1)
- Bump lodash from 4.17.11 to 4.17.15 [#2](https://github.com/pagopa/io-spid-commons/pull/2)
