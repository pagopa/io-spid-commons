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
`1.3.5`.

## Store Additional data between login and acs steps

If you need to pass additional parameters from login request to acs callback,
you can use built-in additional parameter management, by adding a new `extraLoginRequestParamConfig` block in configuration:

```typescript

export type ExtraParamsT = t.TypeOf<typeof ExtraParams>;
export const ExtraParams = t.type({ test: t.string });

const appConfig: IApplicationConfig<ExtraParamsT> = {

  extraLoginRequestParamConfig: {
    codec: ExtraParams,
    requestMapper: (req) =>  
                    ExtraParams.decode({
                                        loginType: req.header("x-test-header"),
                                      })
  },

  assertionConsumerServicePath: "/acs",
  clientErrorRedirectionUrl: "/error",
  clientLoginRedirectionUrl: "/success",
  loginPath: "/login",
  metadataPath: "/metadata",
  sloPath: "/logout",
  spidLevelsWhitelist: ["SpidL2", "SpidL3"],
};
```

The acs callback will receive a second parameter, containing the information extracted during login step for the user:

```typescript

const acs: AssertionConsumerServiceT<ExtraParamsT> = async (
  payload,
  extraParams
  // ^^^ 
  // ExtraParamsT | undefined
) => {
  logger.info("acs:%s%s", JSON.stringify(payload), JSON.stringify(extraParams));
  return ResponsePermanentRedirect({ href: "/success?acs" } as ValidUrl);
};
```

NOTE:   If the mapper or the coded return a validation error, `extraParams` will be undefined.
NOTE 2: It's better to define the codec with defaults and/or partial properties, to avoid undefined values during deploy phase
        (ie: Data stored before the deploy that cannot be decoded with new codec because of lack of required properties)


## Local development

To run the project locally with the embedded example express application run the following commands:

```sh
yarn install
yarn build
docker-compose up --build
```

PS. If was present locally a previously cached version of `io-spid-commons` docker container and you get the error `Unexpected token <` on `node_modules/xml-encription/lib/templates/encrypted-key.tpl.xml.js`, is needed to clean all the old containers datas with `docker system prune --all` before running the project again.
