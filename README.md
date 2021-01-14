[![Build Status](https://dev.azure.com/pagopa-io/io-spid-commons/_apis/build/status/pagopa.io-spid-commons.deploy?branchName=master)](https://dev.azure.com/pagopa-io/io-spid-commons/_build/latest?definitionId=98&branchName=master)
# io-spid-commons

This repo contains:

- a passport-strategy that implements [SPID](https://www.spid.gov.it)
  authentication
- a method that configures an express endpoint to serve Service Provider
  metadata
- a scheduled procedure that refreshes IDP metadata from the [SPID
  registry](https://registry.spid.gov.it)
- a redis cache provider to validate SAML InResponseTo field

You may use this package if you're going to implement a SPID Service Provider
with a NodeJS [express server](https://expressjs.com).

## Upgrading passport-saml

Beware that any changes to the method signatures of
`SAML.prototype.generateAuthorizeRequest` and
`SAML.prototype.validatePostResponse` must be reflected inside the
[`CustomSamlClient`](./strategy/saml_client.ts) class.

That's why the version of passport-saml in package.json is currently fixed at
`1.2.0`.
