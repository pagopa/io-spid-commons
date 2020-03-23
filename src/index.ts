/**
 * Exports a decorator function that applies
 * a SPID authentication middleware to an express application.
 *
 * Setups the endpoint to generate service provider metadata
 * and a scheduled process to refresh IDP metadata from providers.
 */
import * as express from "express";
import { fromNullable, isSome } from "fp-ts/lib/Option";
import { Task, task } from "fp-ts/lib/Task";
import { UTCISODateFromString } from "italia-ts-commons/lib/dates";
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
import * as requestIp from "request-ip";
import { Builder } from "xml2js";
import { noopCacheProvider } from "./strategy/redis_cache_provider";
import { logger } from "./utils/logger";
import { parseStartupIdpsMetadata } from "./utils/metadata";
import {
  getSpidStrategyOptionsUpdater,
  IServiceProviderConfig,
  makeSpidStrategy,
  makeSpidStrategyOptions,
  upsertSpidStrategyOption
} from "./utils/middleware";
import {
  getAuthorizeRequestTamperer,
  getErrorCodeFromResponse,
  getPreValidateResponse,
  getSamlIssuer,
  getSamlOptions,
  getXmlFromSamlResponse
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

export type PayloadType = "REQUEST" | "RESPONSE";

// invoked for each request / response
// to pass SAML payload to the caller
export type DoneCallbackT = (
  sourceIp: string | null,
  payload: string,
  createdAt: UTCISODateFromString,
  payloadType: PayloadType
) => void;

// express endpoints configuration
export interface IApplicationConfig {
  assertionConsumerServicePath: string;
  clientErrorRedirectionUrl: string;
  clientLoginRedirectionUrl: string;
  loginPath: string;
  metadataPath: string;
  sloPath: string;
  startupIdpsMetadata?: Record<string, string>;
}

// re-export
export { noopCacheProvider, IServiceProviderConfig, SamlConfig };

/**
 * Wraps assertion consumer service handler
 * with SPID authentication and redirects.
 */
const withSpidAuthMiddleware = (
  acs: AssertionConsumerServiceT,
  clientLoginRedirectionUrl: string,
  clientErrorRedirectionUrl: string,
  callback?: DoneCallbackT
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
              .getOrElse(`?errorMessage=${err}`)
        );
      }
      if (!user) {
        logger.error(
          "Spid Authentication|Authentication Error|ERROR=user_not_found|ISSUER=%s",
          issuer
        );
        return res.redirect(clientLoginRedirectionUrl);
      }
      if (callback && isSome(maybeDoc)) {
        callback(requestIp.getClientIp(req), req.body, new Date(), "RESPONSE");
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
// tslint:disable-next-line: parameters-max-number
export function withSpid(
  appConfig: IApplicationConfig,
  samlConfig: SamlConfig,
  serviceProviderConfig: IServiceProviderConfig,
  redisClient: RedisClient,
  app: express.Express,
  acs: AssertionConsumerServiceT,
  logout: LogoutT,
  callback?: DoneCallbackT
): Task<{
  app: express.Express;
  idpMetadataRefresher: () => Task<void>;
}> {
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

  const maybeStartupIdpsMetadata = fromNullable(appConfig.startupIdpsMetadata);
  // If `startupIdpsMetadata` is provided, IDP metadata
  // are initially taken from its value when the backend starts
  return maybeStartupIdpsMetadata
    .map(parseStartupIdpsMetadata)
    .map(idpOptionsRecord =>
      task.of(
        makeSpidStrategyOptions(
          samlConfig,
          serviceProviderConfig,
          idpOptionsRecord
        )
      )
    )
    .getOrElse(loadSpidStrategyOptions())
    .map(spidStrategyOptions => {
      upsertSpidStrategyOption(app, spidStrategyOptions);
      return makeSpidStrategy(
        spidStrategyOptions,
        getSamlOptions,
        redisClient,
        authorizeRequestTamperer,
        metadataTamperer,
        getPreValidateResponse(serviceProviderConfig.strictResponseValidation),
        callback
      );
    })
    .map(spidStrategy => {
      // Even when `startupIdpsMetadata` is provided, we try to load
      // IDP metadata from the remote registries
      maybeStartupIdpsMetadata.map(() => {
        loadSpidStrategyOptions()
          .map(opts => upsertSpidStrategyOption(app, opts))
          .run()
          .catch(e => {
            logger.error("loadSpidStrategyOptions|error:%s", e);
          });
      });
      // Fetch IDPs metadata from remote URL and update SPID passport strategy options
      const idpMetadataRefresher = () =>
        loadSpidStrategyOptions().map(opts =>
          upsertSpidStrategyOption(app, opts)
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
          appConfig.clientErrorRedirectionUrl,
          callback
        )
      );

      // Setup logout handler
      app.post(appConfig.sloPath, toExpressHandler(logout));

      return { app, idpMetadataRefresher };
    });
}
