import * as express from "express";
import { fromNullable } from "fp-ts/lib/Option";
import { TaskEither } from "fp-ts/lib/TaskEither";
import * as fs from "fs";
import { toExpressHandler } from "italia-ts-commons/lib/express";
import {
  IResponseErrorInternal,
  IResponseErrorValidation,
  IResponsePermanentRedirect,
  IResponseSuccessXml,
  ResponseErrorInternal,
  ResponsePermanentRedirect,
  ResponseSuccessXml
} from "italia-ts-commons/lib/responses";
import { UrlFromString } from "italia-ts-commons/lib/url";
import * as passport from "passport";
import { SamlConfig } from "passport-saml";
import { Builder } from "xml2js";
import { SpidUser } from "./types/spidUser";
import { logger } from "./utils/logger";
import {
  getSpidStrategyOptionsUpdater,
  IServiceProviderConfig,
  makeSpidStrategy,
  setSpidStrategyOption
} from "./utils/middleware";
import { getErrorCodeFromResponse } from "./utils/response";
import {
  getAuthorizeRequestTamperer,
  getSamlIssuer,
  getSamlOptions
} from "./utils/saml";
import { getMetadataTamperer } from "./utils/saml";

// assertion consumer service express handler
export type AssertionConsumerServiceT = (
  userPayload: SpidUser
) => Promise<
  IResponseErrorInternal | IResponseErrorValidation | IResponsePermanentRedirect
>;

// express endpoints configuration
export interface IApplicationConfig {
  assertionConsumerServicePath: string;
  clientErrorRedirectionUrl: string;
  clientLoginRedirectionUrl: string;
  loginPath: string;
  metadataPath: string;
  sloPath: string;
}

/**
 * Wraps assertion consumer service handler
 * with SPID authentication and redirects.
 */
const withSpidAuthMiddleware = (
  acs: AssertionConsumerServiceT,
  clientErrorRedirectionUrl: string,
  clientLoginRedirectionUrl: string
): express.Handler => {
  return (req, res, next) => {
    passport.authenticate("spid", async (err, user) => {
      const issuer = getSamlIssuer(req.body);
      if (err) {
        logger.error(
          "SPID|Authentication Error|ERROR=%s|ISSUER=%s",
          err,
          issuer
        );
        return ResponsePermanentRedirect(
          ((clientErrorRedirectionUrl +
            fromNullable(err.statusXml)
              .chain(statusXml => getErrorCodeFromResponse(statusXml))
              .map(errorCode => `?errorCode=${errorCode}`)
              .getOrElse("")) as unknown) as UrlFromString
        );
      }
      if (!user) {
        logger.error(
          "SPID|Authentication Error|ERROR=user_not_found|ISSUER=%s",
          issuer
        );
        return ResponsePermanentRedirect(
          (clientLoginRedirectionUrl as unknown) as UrlFromString
        );
      }
      return acs(user);
    })(req, res, next);
  };
};

/**
 * Apply SPID authentication middleware
 * to an express application.
 */
export function withSpid(
  appConfig: IApplicationConfig,
  samlConfig: SamlConfig,
  serviceProviderConfig: IServiceProviderConfig,
  app: express.Express,
  acs: AssertionConsumerServiceT
): TaskEither<Error, express.Express> {
  const loadSpidStrategyOptions = getSpidStrategyOptionsUpdater(
    samlConfig,
    serviceProviderConfig
  );

  const metadataTamperer = getMetadataTamperer(
    new Builder(),
    serviceProviderConfig,
    samlConfig
  );
  const authorizeRequestTamperer = getAuthorizeRequestTamperer(
    // spid-testenv does not accept an xml header with utf8 encoding
    new Builder({ xmldec: { encoding: undefined, version: "1.0" } }),
    serviceProviderConfig,
    samlConfig
  );

  return loadSpidStrategyOptions()
    .map(spidStrategyOptions => {
      setSpidStrategyOption(app, spidStrategyOptions);
      return makeSpidStrategy(
        spidStrategyOptions,
        getSamlOptions,
        authorizeRequestTamperer,
        metadataTamperer
      );
    })
    .map(spidStrategy => {
      // install express middleware to get and refresh
      // SPID passport strategy options
      app.use(async (req, __, next) =>
        loadSpidStrategyOptions()
          .map(opts => setSpidStrategyOption(req.app, opts))
          .run()
          .then(() => next())
          .catch(e => {
            logger.error("loadSpidStrategyOptions#error:%s", e.toString());
            next(e);
          })
      );

      // Initializes SpidStrategy for passport
      passport.use("spid", spidStrategy);

      const spidAuth = passport.authenticate("spid", {
        session: false
      });

      // Setup SPID login handler
      app.get(appConfig.loginPath, spidAuth);

      // Setup SPID metadata handler
      app.get(
        appConfig.metadataPath,
        toExpressHandler(
          async (
            req
          ): Promise<IResponseErrorInternal | IResponseSuccessXml<string>> =>
            new Promise(resolve =>
              spidStrategy.generateServiceProviderMetadataAsync(
                req,
                null,
                serviceProviderConfig.publicCert,
                (err, metadata) => {
                  if (err || !metadata) {
                    resolve(
                      ResponseErrorInternal(
                        err
                          ? err.message
                          : "Error generating service provider metadata."
                      )
                    );
                  } else {
                    resolve(ResponseSuccessXml(metadata));
                  }
                }
              )
            )
        )
      );

      // Setup SPID assertion consumer service.
      // This endpoint is called when the SPID IDP
      // redirects the authenticated user to our app
      app.post(appConfig.assertionConsumerServicePath, () =>
        withSpidAuthMiddleware(
          acs,
          appConfig.clientErrorRedirectionUrl,
          appConfig.clientLoginRedirectionUrl
        )
      );

      // Setup logout handler
      app.post(appConfig.sloPath, () =>
        toExpressHandler(async () =>
          ResponsePermanentRedirect(
            UrlFromString.decode(appConfig.loginPath).getOrElse(new URL("/"))
          )
        )
      );

      return app;
    });
}

///////////

const appConfigL: IApplicationConfig = {
  assertionConsumerServicePath: "/acs",
  clientErrorRedirectionUrl: "/ko",
  clientLoginRedirectionUrl: "/ok",
  loginPath: "/login",
  metadataPath: "/metadata.xml",
  sloPath: "/logout"
};

const serviceProviderConfigL: IServiceProviderConfig = {
  IDPMetadataUrl:
    "https://registry.spid.gov.it/metadata/idp/spid-entities-idps.xml",
  hasSpidValidatorEnabled: true,
  organization: {
    URL: "https://example.com",
    displayName: "Organization display name",
    name: "Organization name"
  },
  publicCert: fs.readFileSync("./certs/cert.pem", "utf-8"),
  requiredAttributes: {
    attributes: ["address"],
    name: "Required attrs"
  },
  spidTestEnvUrl: "https://spid-testenv2:8088"
};

const samlConfigL: SamlConfig = {
  acceptedClockSkewMs: 0,
  attributeConsumingServiceIndex: "0",
  authnContext: "https://www.spid.gov.it/SpidL1",
  callbackUrl: "http://localhost:3000/acs",
  // decryptionPvk: fs.readFileSync("./certs/key.pem", "utf-8"),
  identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
  issuer: "https://spid.agid.gov.it/cd",
  logoutCallbackUrl: "http://localhost:3000/slo",
  privateCert: fs.readFileSync("./certs/key.pem", "utf-8")
};

// demo acs
const demoAcsL = async () =>
  ResponsePermanentRedirect(("/ok" as unknown) as UrlFromString);

const appL = express();

withSpid(appConfigL, samlConfigL, serviceProviderConfigL, appL, demoAcsL)
  .map(app => {
    app.get("/ok", (req, res) => res.json({ ok: "ok" }));
    app.get("/ko", (req, res) => res.json({ ok: "ko" }));
    // tslint:disable-next-line: no-any
    app.use(
      (
        error: Error,
        _: express.Request,
        res: express.Response,
        ___: express.NextFunction
      ) => res.status(500).send(error)
    );
    app.listen(3000);
  })
  .run()
  // tslint:disable-next-line: no-console
  .catch(e => console.error("caught error: ", e));
