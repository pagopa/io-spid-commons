# io-spid-commons

This repo contains:

- a passport-strategy that implements a [SPID](https://www.spid.gov.it) login
- express endpoints and middlewares to server Service Provider metadata and get
  IDP metadata from [SPID registry](https://registry.spid.gov.it)

Use this package to implement a SPID Service Provider with a NodeJS [express
server](https://expressjs.com).

## Upgrading passport-saml

Beware that any changes to the method signatures of
`SAML.prototype.generateAuthorizeRequest` and
`SAML.prototype.validatePostResponse` must be reflected inside the
[`CustomSamlClient`]() class.

That's why the version of passport-saml in package.json is currently fixed at
`1.2.0`.
