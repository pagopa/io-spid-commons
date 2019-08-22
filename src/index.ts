import { Express, Request, Response } from "express";
import { not } from "fp-ts/lib/function";
import {
  IResponse,
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
import { isSpidL, SpidLevel } from "./types/spidLevel";
import { matchRoute } from "./utils/express";
import getErrorCodeFromResponse from "./utils/getErrorCodeFromResponse";
import { log } from "./utils/logger";

export const SPID_RELOAD_ERROR = new Error(
  "Error while initializing SPID strategy"
);

export const SPID_STRATEGY_NOT_DEFINED = new Error(
  "Spid Strategy not defined."
);

export {
  getErrorCodeFromResponse,
  isSpidL,
  IIoSpidStrategy,
  ISpidStrategyConfig,
  SamlAttribute,
  SpidLevel
};

export class SpidPassportBuilder {
  private spidStrategy?: IIoSpidStrategy;
  private loginPath: string;
  private metadataPath: string;
  private metadataXml?: string;
  private config: ISpidStrategyConfig;
  private app: Express;

  constructor(
    app: Express,
    loginPath: string,
    metadataPath: string,
    config: ISpidStrategyConfig
  ) {
    this.loginPath = loginPath;
    this.metadataPath = metadataPath;
    this.config = config;
    this.app = app;
  }

  /**
   * Initializes SpidStrategy for passport and setup login route.
   */
  public async init(): Promise<void> {
    // tslint:disable-next-line: no-object-mutation
    this.spidStrategy = await loadSpidStrategy(this.config);
    this.registerLoginRoute(this.spidStrategy);
  }

  public async clearAndReloadSpidStrategy(
    newConfig?: ISpidStrategyConfig
  ): Promise<void> {
    log.info("Started Spid strategy re-initialization ...");
    try {
      const newSpidStrategy: IIoSpidStrategy = await loadSpidStrategy(
        newConfig || this.config
      );
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
    } catch (err) {
      log.error("Error on update spid strategy: %s", err);
      throw SPID_RELOAD_ERROR;
    }
  }

  private registerLoginRoute(spidStrategy: IIoSpidStrategy): void {
    passport.use("spid", spidStrategy);
    const spidAuth = passport.authenticate("spid", { session: false });
    this.app.get(this.loginPath, spidAuth);
    this.app.get(this.metadataPath, this.toExpressHandler(this.metadata, this));
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
