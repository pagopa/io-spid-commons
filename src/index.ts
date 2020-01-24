// tslint:disable no-commented-code no-console

import * as express from "express";
import { fromNullable } from "fp-ts/lib/Option";
import { TaskEither, taskify } from "fp-ts/lib/TaskEither";
import * as fs from "fs";
import { toExpressHandler } from "italia-ts-commons/lib/express";
import {
  IResponseErrorInternal,
  IResponseErrorValidation,
  IResponsePermanentRedirect,
  IResponseSuccessXml,
  ResponseErrorInternal,
  ResponseErrorNotFound,
  ResponsePermanentRedirect,
  ResponseSuccessXml
} from "italia-ts-commons/lib/responses";
import { UrlFromString } from "italia-ts-commons/lib/url";
import * as passport from "passport";
import { SamlConfig } from "passport-saml";
import {
  getSpidStrategyOptionsUpdater,
  IServiceProviderConfig,
  makeSpidStrategy
} from "./strategies/SpidStrategy";
import { SpidUser } from "./types/spidUser";
import { logger } from "./utils/logger";
import { getErrorCodeFromResponse } from "./utils/response";
import { getSamlIssuer } from "./utils/saml";
import { getServiceProviderMetadata } from "./utils/saml";

export type AssertionConsumerServiceT = (
  userPayload: SpidUser
) => Promise<
  IResponseErrorInternal | IResponseErrorValidation | IResponsePermanentRedirect
>;

export interface IApplicationConfig {
  assertionConsumerServicePath: string;
  clientErrorRedirectionUrl: string;
  clientLoginRedirectionUrl: string;
  loginPath: string;
  metadataPath: string;
  sloPath: string;
}

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
  return loadSpidStrategyOptions()
    .map(spidStrategyOptions => makeSpidStrategy(spidStrategyOptions))
    .map(spidStrategy => {
      // install express middleware to get SPID passport strategy options
      // TODO: memoize this
      app.use(async (req, _, next) => {
        return (
          loadSpidStrategyOptions()
            .map(opts => req.app.set("spidStrategyOptions", opts))
            .run()
            // tslint:disable-next-line: no-console
            .then(() => next())
            .catch(e => {
              console.error("loadSpidStrategyOptions", e);
              next(e);
            })
        );
      });

      // Initializes SpidStrategy for passport and setup login and auth routes.

      passport.use("spid", spidStrategy);

      const spidAuth = passport.authenticate("spid", {
        session: false
      });

      app.get(appConfig.loginPath, spidAuth);

      app.get(
        appConfig.metadataPath,
        toExpressHandler(async req => {
          return typeof samlConfig.privateCert === "string"
            ? getServiceProviderMetadata(
                spidStrategy,
                serviceProviderConfig,
                samlConfig,
                req
              )
                .fold<IResponseSuccessXml<string> | IResponseErrorInternal>(
                  err => ResponseErrorInternal(err.message),
                  ResponseSuccessXml
                )
                .run()
            : ResponseErrorNotFound(
                "Not found.",
                "Metadata does not have a valid cert assigned."
              );
        })
      );

      app.post(appConfig.assertionConsumerServicePath, () =>
        withSpidAuthMiddleware(
          acs,
          appConfig.clientErrorRedirectionUrl,
          appConfig.clientLoginRedirectionUrl
        )
      );

      // TODO: check this one
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
