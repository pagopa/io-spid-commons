import { Express } from "express";
import { not } from "fp-ts/lib/function";
import * as passport from "passport";
import { SpidStrategy } from "spid-passport";
import loadSpidStrategy, {
  ISpidStrategyConfig
} from "./strategies/spidStrategy";
import { SpidUser } from "./types/user";
import { log } from "./utils/logger";

export class SpidPassport {
  public spidStrategy?: SpidStrategy<SpidUser>;
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
  ): Promise<SpidStrategy<SpidUser>> {
    log.info("Started Spid strategy re-initialization ...");
    try {
      const newSpidStrategy: SpidStrategy<SpidUser> = await loadSpidStrategy(
        newConfig || this.config
      );
      if (newConfig) {
        // tslint:disable-next-line: no-object-mutation
        this.config = newConfig;
      }
      passport.unuse("spid");
      // tslint:disable-next-line: no-any
      const isLoginRoute = (route: any) =>
        route.route &&
        route.route.path === this.loginPath &&
        route.route.methods &&
        route.route.methods.get;

      // Remove login route from Express router stack
      // tslint:disable-next-line: no-object-mutation
      this.app._router.stack = this.app._router.stack.filter(not(isLoginRoute));
      this.registerLoginRoute(newSpidStrategy);
      log.info("Spid strategy re-initialization complete.");
      return newSpidStrategy;
    } catch (err) {
      log.error("Error on update spid strategy: %s", err);
      throw new Error("Error while initializing SPID strategy");
    }
  }

  private registerLoginRoute(spidStrategy: SpidStrategy<SpidUser>): void {
    passport.use("spid", spidStrategy);
    const spidAuth = passport.authenticate("spid", { session: false });
    this.app.get(this.loginPath, spidAuth);
  }
}
