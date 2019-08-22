import { Express } from "express";
import { not } from "fp-ts/lib/function";
import * as passport from "passport";
import {
  IIoSpidStrategy,
  ISpidStrategyConfig,
  loadSpidStrategy,
  SamlAttribute
} from "./strategies/spidStrategy";
import { matchRoute } from "./utils/express";
import { log } from "./utils/logger";

export const SPID_RELOAD_ERROR = new Error(
  "Error while initializing SPID strategy"
);

export { IIoSpidStrategy, ISpidStrategyConfig, SamlAttribute };

export class SpidPassportBuilder {
  public spidStrategy?: IIoSpidStrategy;
  private loginPath: string;
  private config: ISpidStrategyConfig;
  private app: Express;

  constructor(app: Express, path: string, config: ISpidStrategyConfig) {
    this.loginPath = path;
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
  ): Promise<IIoSpidStrategy> {
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
      this.registerLoginRoute(newSpidStrategy);
      log.info("Spid strategy re-initialization complete.");
      return newSpidStrategy;
    } catch (err) {
      log.error("Error on update spid strategy: %s", err);
      throw SPID_RELOAD_ERROR;
    }
  }

  private registerLoginRoute(spidStrategy: IIoSpidStrategy): void {
    passport.use("spid", spidStrategy);
    const spidAuth = passport.authenticate("spid", { session: false });
    this.app.get(this.loginPath, spidAuth);
  }
}
