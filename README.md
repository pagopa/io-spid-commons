[![License](https://img.shields.io/github/license/italia/spid-express.svg)](https://github.com/italia/spid-express/blob/master/LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/italia/spid-express.svg)](https://github.com/italia/spid-express/issues)
[![Join the #spid-express channel](https://img.shields.io/badge/Slack%20channel-%23design-blue.svg)](https://app.slack.com/client/T6C27AXE0/C7ESTJS58)
[![Get invited](https://slack.developers.italia.it/badge.svg)](https://slack.developers.italia.it/)
[![SPID on forum.italia.it](https://img.shields.io/badge/Forum-18app-blue.svg)](https://forum.italia.it/c/spid/5)

# spid-express

This repo contains:

- a passport-strategy that implements [SPID](https://www.spid.gov.it) authentication
- a method that configures an express endpoint to serve Service Provider metadata
- a scheduled procedure that refreshes IDP metadata from the [SPID registry](https://registry.spid.gov.it)
- a redis cache provider to validate SAML `InResponseTo` field

You may use this package if you're going to implement a SPID Service Provider with a NodeJS [express server](https://expressjs.com).

## Upgrading passport-saml

Beware that any changes to the method signatures of
`SAML.prototype.generateAuthorizeRequest` and `SAML.prototype.validatePostResponse` must be reflected inside the
[`CustomSamlClient`](./strategy/saml_client.ts) class.

That's why the version of passport-saml in package.json is currently fixed at `1.2.0`.

# Licence
This repository is covered by an [MIT license](LICENSE)


