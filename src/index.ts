import { Express, NextFunction, Request, Response } from "express";
import { not } from "fp-ts/lib/function";
import { fromNullable } from "fp-ts/lib/Option";
import { TaskEither } from "fp-ts/lib/TaskEither";
import {
  IResponse,
  IResponseErrorInternal,
  IResponseErrorValidation,
  IResponsePermanentRedirect,
  IResponseSuccessXml,
  ResponseErrorInternal,
  ResponseSuccessXml
} from "italia-ts-commons/lib/responses";
import * as passport from "passport";
import {
  IIoSpidStrategy,
  ISpidStrategyConfig,
  loadSpidStrategy,
  SamlAttribute
} from "./strategies/spidStrategy";
import { isSpidL, SpidLevel, SpidLevelEnum } from "./types/spidLevel";
import { matchRoute } from "./utils/express";
import { log } from "./utils/logger";
import {
  getAuthnContextFromResponse,
  getErrorCodeFromResponse
} from "./utils/response";
import { getSamlIssuer } from "./utils/saml";

export const SPID_RELOAD_ERROR = new Error(
  "Error while initializing SPID strategy"
);

export const SPID_STRATEGY_NOT_DEFINED = new Error(
  "Spid Strategy not defined."
);

export interface IAuthenticationController {
  acs: (
    userPayload: unknown
  ) => Promise<
    | IResponseErrorInternal
    | IResponseErrorValidation
    | IResponsePermanentRedirect
  >;
  slo: () => Promise<IResponsePermanentRedirect>;
}

export {
  getAuthnContextFromResponse,
  getErrorCodeFromResponse,
  isSpidL,
  IIoSpidStrategy,
  ISpidStrategyConfig,
  SamlAttribute,
  SpidLevel,
  SpidLevelEnum
};

export class SpidPassportBuilder {
  private spidStrategy?: IIoSpidStrategy;
  private loginPath: string;
  private sloPath: string;
  private assertionConsumerServicePath: string;
  private metadataPath: string;
  private metadataXml?: string;
  private config: ISpidStrategyConfig;
  private app: Express;

  constructor(
    app: Express,
    loginPath: string,
    sloPath: string,
    assertionConsumerServicePath: string,
    metadataPath: string,
    config: ISpidStrategyConfig
  ) {
    this.loginPath = loginPath;
    this.metadataPath = metadataPath;
    this.sloPath = sloPath;
    this.assertionConsumerServicePath = assertionConsumerServicePath;
    this.config = config;
    this.app = app;
  }

  /**
   * Initializes SpidStrategy for passport and setup login and auth routes.
   */
  public init(
    authenticationController: IAuthenticationController,
    clientErrorRedirectionUrl: string,
    clientLoginRedirectionUrl: string
  ): TaskEither<Error, void> {
    return loadSpidStrategy(this.config).map(ioSpidStrategy => {
      // tslint:disable-next-line: no-object-mutation
      this.spidStrategy = ioSpidStrategy;
      this.registerLoginRoute(this.spidStrategy);
      this.registerAuthRoutes(
        authenticationController,
        clientErrorRedirectionUrl,
        clientLoginRedirectionUrl
      );
    });
  }

  public clearAndReloadSpidStrategy(
    newConfig?: ISpidStrategyConfig
  ): TaskEither<Error, void> {
    log.info("Started Spid strategy re-initialization ...");
    return loadSpidStrategy(newConfig || this.config)
      .map(spidStrategy => {
        const newSpidStrategy: IIoSpidStrategy = spidStrategy;
        if (newConfig) {
          // tslint:disable-next-line: no-object-mutation
          this.config = newConfig;
        }
        passport.unuse("spid");
        // tslint:disable-next-line: no-any

        // Remove login route from Express router stack
        // tslint:disable-next-line: no-object-mutation
        this.app._router.stack = this.app._router.stack.filter(
          not(matchRoute(this.loginPath, "get"))
        );
        // tslint:disable-next-line: no-object-mutation
        this.metadataXml = undefined;
        this.registerLoginRoute(newSpidStrategy);
        log.info("Spid strategy re-initialization complete.");
      })
      .mapLeft(error => {
        log.error("Error on update spid strategy: %s", error);
        return SPID_RELOAD_ERROR;
      });
  }

  private registerLoginRoute(spidStrategy: IIoSpidStrategy): void {
    passport.use("spid", spidStrategy);
    const spidAuth = passport.authenticate("spid", { session: false });
    this.app.get(this.loginPath, spidAuth);
    this.app.get(this.metadataPath, this.toExpressHandler(this.metadata, this));
  }

  private registerAuthRoutes(
    acsController: IAuthenticationController,
    clientErrorRedirectionUrl: string,
    clientLoginRedirectionUrl: string
  ): void {
    this.app.post(
      this.assertionConsumerServicePath,
      this.withSpidAuth(
        acsController,
        clientErrorRedirectionUrl,
        clientLoginRedirectionUrl
      )
    );

    this.app.post(
      this.sloPath,
      this.toExpressHandler(acsController.slo, acsController)
    );
  }

  /**
   * Catch SPID authentication errors and redirect the client to
   * clientErrorRedirectionUrl.
   */
  private withSpidAuth(
    controller: IAuthenticationController,
    clientErrorRedirectionUrl: string,
    clientLoginRedirectionUrl: string
  ): (req: Request, res: Response, next: NextFunction) => void {
    return (req: Request, res: Response, next: NextFunction) => {
      passport.authenticate("spid", async (err, user) => {
        const issuer = getSamlIssuer(req.body);
        if (err) {
          log.error(
            "Spid Authentication|Authentication Error|ERROR=%s|ISSUER=%s",
            err,
            issuer
          );
          return res.redirect(
            clientErrorRedirectionUrl +
              fromNullable(err.statusXml)
                .chain(statusXml => getErrorCodeFromResponse(statusXml))
                .map(errorCode => `?errorCode=${errorCode}`)
                .getOrElse("")
          );
        }
        if (!user) {
          log.error(
            "Spid Authentication|Authentication Error|ERROR=user_not_found|ISSUER=%s",
            issuer
          );
          return res.redirect(clientLoginRedirectionUrl);
        }
        const response = await controller.acs(user);
        response.apply(res);
      })(req, res, next);
    };
  }

  private toExpressHandler<T, P>(
    handler: (req: Request) => Promise<IResponse<T>>,
    object?: P
  ): (req: Request, res: Response) => void {
    return (req, res) =>
      handler
        .call(object, req)
        .catch(ResponseErrorInternal)
        .then(response => {
          // tslint:disable-next-line:no-object-mutation
          res.locals.detail = response.detail;
          response.apply(res);
        });
  }

  /**
   * The metadata for this Service Provider.
   */
  private async metadata(): Promise<IResponseSuccessXml<string>> {
    if (this.spidStrategy === undefined) {
      return Promise.reject(SPID_STRATEGY_NOT_DEFINED);
    }
    if (this.metadataXml === undefined) {
      // tslint:disable-next-line: no-object-mutation
      this.metadataXml = this.spidStrategy.generateServiceProviderMetadata(
        this.config.samlCert
      );
    }
    return ResponseSuccessXml(this.metadataXml);
  }
}
