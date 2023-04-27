/**
 * Exports a decorator function that applies
 * a SPID authentication middleware to an express application.
 *
 * Setups the endpoint to generate service provider metadata
 * and a scheduled process to refresh IDP metadata from providers.
 */
import { toExpressHandler } from "@pagopa/ts-commons/lib/express";
import {
  IResponseErrorForbiddenNotAuthorized,
  IResponseErrorInternal,
  IResponseErrorValidation,
  IResponsePermanentRedirect,
  IResponseSuccessXml,
  ResponseErrorInternal,
  ResponseErrorValidation,
  ResponseSuccessXml
} from "@pagopa/ts-commons/lib/responses";
import * as express from "express";
import { constVoid, pipe } from "fp-ts/lib/function";
import * as O from "fp-ts/lib/Option";
import * as T from "fp-ts/lib/Task";
import * as t from "io-ts";
import * as passport from "passport";
import { SamlConfig } from "passport-saml";
import { RedisClient } from "redis";
import { Builder } from "xml2js";
import { SPID_LEVELS } from "./config";
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
import { middlewareCatchAsInternalError } from "./utils/response";
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
  | IResponseErrorInternal
  | IResponseErrorValidation
  | IResponsePermanentRedirect
  | IResponseErrorForbiddenNotAuthorized
>;

// logout express handler
export type LogoutT = () => Promise<IResponsePermanentRedirect>;

// invoked for each request / response
// to pass SAML payload to the caller
export type DoneCallbackT = (
  sourceIp: string | null,
  request: string,
  response: string
) => void;

export interface IEventInfo {
  readonly name: string;
  readonly type: "ERROR" | "INFO";
  readonly data: {
    readonly [key: string]: string;
    readonly message: string;
  };
}

export type EventTracker = (params: IEventInfo) => void;

// express endpoints configuration
export interface IApplicationConfig {
  readonly assertionConsumerServicePath: string;
  readonly clientErrorRedirectionUrl: string;
  readonly clientLoginRedirectionUrl: string;
  readonly loginPath: string;
  readonly metadataPath: string;
  readonly sloPath: string;
  readonly spidLevelsWhitelist: ReadonlyArray<keyof SPID_LEVELS>;
  readonly startupIdpsMetadata?: Record<string, string>;
  readonly eventTraker?: EventTracker;
  readonly hasClockSkewLoggingEvent?: boolean;
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
  clientErrorRedirectionUrl: string
) => (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): void => {
  passport.authenticate("spid", async (err: unknown, user: unknown) => {
    const maybeDoc = getXmlFromSamlResponse(req.body);
    const issuer = pipe(
      maybeDoc,
      O.chain(getSamlIssuer),
      O.getOrElse(() => "UNKNOWN")
    );
    if (err) {
      const redirectionUrl =
        clientErrorRedirectionUrl +
        pipe(
          maybeDoc,
          O.chain(getErrorCodeFromResponse),
          O.map(errorCode => `?errorCode=${errorCode}`),
          O.getOrElse(() => `?errorMessage=${err}`)
        );
      logger.error(
        "Spid Authentication|Authentication Error|ERROR=%s|ISSUER=%s|REDIRECT_TO=%s",
        err,
        issuer,
        redirectionUrl
      );
      return res.redirect(redirectionUrl);
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

type ExpressMiddleware = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => void;
interface IWithSpidT {
  readonly appConfig: IApplicationConfig;
  readonly samlConfig: SamlConfig;
  readonly serviceProviderConfig: IServiceProviderConfig;
  readonly redisClient: RedisClient;
  readonly app: express.Express;
  readonly acs: AssertionConsumerServiceT;
  readonly logout: LogoutT;
  readonly doneCb?: DoneCallbackT;
  readonly lollipopMiddleware?: ExpressMiddleware;
}

/**
 * Apply SPID authentication middleware
 * to an express application.
 */
// eslint-disable-next-line max-params
export const withSpid = ({
  acs,
  app,
  appConfig,
  doneCb = constVoid,
  logout,
  redisClient,
  samlConfig,
  serviceProviderConfig,
  lollipopMiddleware = (_, __, next): void => next()
}: IWithSpidT): T.Task<{
  readonly app: express.Express;
  readonly idpMetadataRefresher: () => T.Task<void>;
}> => {
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
    samlConfig
  );

  const maybeStartupIdpsMetadata = O.fromNullable(
    appConfig.startupIdpsMetadata
  );
  // If `startupIdpsMetadata` is provided, IDP metadata
  // are initially taken from its value when the backend starts
  return pipe(
    maybeStartupIdpsMetadata,
    O.map(parseStartupIdpsMetadata),
    O.map(idpOptionsRecord =>
      T.of(
        makeSpidStrategyOptions(
          samlConfig,
          serviceProviderConfig,
          idpOptionsRecord
        )
      )
    ),
    O.getOrElse(loadSpidStrategyOptions),
    T.map(spidStrategyOptions => {
      upsertSpidStrategyOption(app, spidStrategyOptions);
      return makeSpidStrategy(
        spidStrategyOptions,
        getSamlOptions,
        redisClient,
        authorizeRequestTamperer,
        metadataTamperer,
        getPreValidateResponse(
          serviceProviderConfig.strictResponseValidation,
          appConfig.eventTraker,
          appConfig.hasClockSkewLoggingEvent
        ),
        doneCb
      );
    }),
    T.map(spidStrategy => {
      // Even when `startupIdpsMetadata` is provided, we try to load
      // IDP metadata from the remote registries
      pipe(
        maybeStartupIdpsMetadata,
        O.map(() => {
          pipe(
            loadSpidStrategyOptions(),
            T.map(opts => upsertSpidStrategyOption(app, opts))
          )().catch(e => {
            logger.error("loadSpidStrategyOptions|error:%s", e);
          });
        })
      );
      // Fetch IDPs metadata from remote URL and update SPID passport strategy options
      const idpMetadataRefresher = (): T.Task<void> =>
        pipe(
          loadSpidStrategyOptions(),
          T.map(opts => upsertSpidStrategyOption(app, opts))
        );

      // Initializes SpidStrategy for passport
      passport.use("spid", spidStrategy);

      const spidAuth = passport.authenticate("spid", {
        session: false
      });

      // Setup SPID login handler
      app.get(
        appConfig.loginPath,
        middlewareCatchAsInternalError((req, res, next) => {
          pipe(
            O.fromNullable(req.query),
            O.chainNullableK(q => q.authLevel),
            O.filter(t.keyof(SPID_LEVELS).is),
            O.chain(
              O.fromPredicate(authLevel =>
                appConfig.spidLevelsWhitelist.includes(authLevel)
              )
            ),
            O.fold(
              () => {
                logger.error(
                  `Missing or invalid authLevel [${req?.query?.authLevel}]`
                );
                return ResponseErrorValidation(
                  "Bad Request",
                  "Missing or invalid authLevel"
                ).apply(res);
              },
              _ => next()
            )
          );
        }),
        middlewareCatchAsInternalError(lollipopMiddleware),
        middlewareCatchAsInternalError(spidAuth)
      );

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
        middlewareCatchAsInternalError(
          withSpidAuthMiddleware(
            acs,
            appConfig.clientLoginRedirectionUrl,
            appConfig.clientErrorRedirectionUrl
          )
        )
      );

      // Setup logout handler
      app.post(appConfig.sloPath, toExpressHandler(logout));

      return { app, idpMetadataRefresher };
    })
  );
};
