import { Express } from "express";
import { not } from "fp-ts/lib/function";
import * as passport from "passport";
import { SpidStrategy } from "spid-passport";
import loadSpidStrategy, {
  ISpidStrategyConfig
} from "./strategies/spidStrategy";
import { SpidUser } from "./types/user";
import { log } from "./utils/logger";

// tslint:disable-next-line: no-let
let loginPath: string;
/**
 * Initializes SpidStrategy for passport and setup /login route.
 */
export async function init(
  app: Express,
  path: string,
  config: ISpidStrategyConfig
): Promise<SpidStrategy<SpidUser>> {
  // Add the strategy to authenticate the proxy to SPID.
  loginPath = path;
  const spidStrategy = await loadSpidStrategy(config);
  registerLoginRoute(app, spidStrategy);
  return spidStrategy;
}

function registerLoginRoute(
  app: Express,
  spidStrategy: SpidStrategy<SpidUser>
): void {
  passport.use("spid", spidStrategy);
  const spidAuth = passport.authenticate("spid", { session: false });
  app.get(loginPath, spidAuth);
}

export async function clearAndReloadSpidStrategy(
  app: Express,
  config: ISpidStrategyConfig
): Promise<SpidStrategy<SpidUser>> {
  log.info("Started Spid strategy re-initialization ...");
  try {
    const newSpidStrategy: SpidStrategy<SpidUser> = await loadSpidStrategy(
      config
    );
    passport.unuse("spid");
    // tslint:disable-next-line: no-any
    const isLoginRoute = (route: any) =>
      route.route &&
      route.route.path === loginPath &&
      route.route.methods &&
      route.route.methods.get;

    // Remove login route from Express router stack
    // tslint:disable-next-line: no-object-mutation
    app._router.stack = app._router.stack.filter(not(isLoginRoute));
    registerLoginRoute(app, newSpidStrategy);
    log.info("Spid strategy re-initialization complete.");
    return newSpidStrategy;
  } catch (err) {
    log.error("Error on update spid strategy: %s", err);
    throw new Error("Error while initializing SPID strategy");
  }
}
