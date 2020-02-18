/**
 * Exports a decorator function that applies
 * a SPID authentication middleware to an express application.
 *
 * Setups the endpoint to generate service provider metadata
 * and a scheduled process to refresh IDP metadata from providers.
 */
import * as express from "express";
import { TaskEither } from "fp-ts/lib/TaskEither";
import { toExpressHandler } from "italia-ts-commons/lib/express";
import {
  IResponseErrorInternal,
  IResponseErrorValidation,
  IResponsePermanentRedirect,
  IResponseSuccessXml,
  ResponseErrorInternal,
  ResponseSuccessXml
} from "italia-ts-commons/lib/responses";
import * as passport from "passport";
import { SamlConfig } from "passport-saml";
import { RedisClient } from "redis";
import { Builder } from "xml2js";
import { logger } from "./utils/logger";
import {
  getSpidStrategyOptionsUpdater,
  IServiceProviderConfig,
  makeSpidStrategy,
  setSpidStrategyOption
} from "./utils/middleware";
import {
  getAuthorizeRequestTamperer,
  getErrorCodeFromResponse,
  getSamlIssuer,
  getSamlOptions,
  getXmlFromSamlResponse,
  preValidateResponse
} from "./utils/saml";
import { getMetadataTamperer } from "./utils/saml";

// assertion consumer service express handler
export type AssertionConsumerServiceT = (
  userPayload: unknown
) => Promise<
  IResponseErrorInternal | IResponseErrorValidation | IResponsePermanentRedirect
>;

// logout express handler
export type LogoutT = () => Promise<IResponsePermanentRedirect>;

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
  clientLoginRedirectionUrl: string,
  clientErrorRedirectionUrl: string
): ((
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => void) => {
  return (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    passport.authenticate("spid", async (err, user) => {
      const maybeDoc = getXmlFromSamlResponse(req.body);
      const issuer = maybeDoc.chain(getSamlIssuer).getOrElse("UNKNOWN");
      if (err) {
        logger.error(
          "Spid Authentication|Authentication Error|ERROR=%s|ISSUER=%s",
          err,
          issuer
        );
        return res.redirect(
          clientErrorRedirectionUrl +
            maybeDoc
              .chain(getErrorCodeFromResponse)
              .map(errorCode => `?errorCode=${errorCode}`)
              .getOrElse("")
        );
      }
      if (!user) {
        logger.error(
          "Spid Authentication|Authentication Error|ERROR=user_not_found|ISSUER=%s",
          issuer
        );
        return res.redirect(clientLoginRedirectionUrl);
      }
      const response = await acs(user);
      response.apply(res);
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
  redisClient: RedisClient,
  serviceProviderConfig: IServiceProviderConfig,
  app: express.Express,
  acs: AssertionConsumerServiceT,
  logout: LogoutT
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
        redisClient,
        authorizeRequestTamperer,
        metadataTamperer,
        preValidateResponse
      );
    })
    .map(spidStrategy => {
      // Schedule get and refresh
      // SPID passport strategy options
      const idpMetadataRefreshTimer = setInterval(
        () =>
          loadSpidStrategyOptions()
            .map(opts => setSpidStrategyOption(app, opts))
            .run()
            .catch(e => {
              logger.error("loadSpidStrategyOptions|error:%s", e);
            }),
        serviceProviderConfig.idpMetadataRefreshIntervalMillis
      );

      // Avoid hanging when express server exits
      app.on("server:stop", () => clearInterval(idpMetadataRefreshTimer));

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
                null, // certificate used for encryption / decryption
                serviceProviderConfig.publicCert,
                (err, metadata) => {
                  if (err || !metadata) {
                    resolve(
                      ResponseErrorInternal(
                        err
                          ? err.message
                          : `Error generating service provider metadata ${err}.`
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
      app.post(
        appConfig.assertionConsumerServicePath,
        withSpidAuthMiddleware(
          acs,
          appConfig.clientLoginRedirectionUrl,
          appConfig.clientErrorRedirectionUrl
        )
      );

      // Setup logout handler
      app.post(appConfig.sloPath, toExpressHandler(logout));

      return app;
    });
}
