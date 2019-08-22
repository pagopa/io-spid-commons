"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const function_1 = require("fp-ts/lib/function");
const passport = require("passport");
const spidStrategy_1 = require("./strategies/spidStrategy");
exports.SamlAttribute = spidStrategy_1.SamlAttribute;
const express_1 = require("./utils/express");
const logger_1 = require("./utils/logger");
exports.SPID_RELOAD_ERROR = new Error("Error while initializing SPID strategy");
class SpidPassportBuilder {
    constructor(app, path, config) {
        this.loginPath = path;
        this.config = config;
        this.app = app;
    }
    /**
     * Initializes SpidStrategy for passport and setup login route.
     */
    async init() {
        // tslint:disable-next-line: no-object-mutation
        this.spidStrategy = await spidStrategy_1.loadSpidStrategy(this.config);
        this.registerLoginRoute(this.spidStrategy);
    }
    async clearAndReloadSpidStrategy(newConfig) {
        logger_1.log.info("Started Spid strategy re-initialization ...");
        try {
            const newSpidStrategy = await spidStrategy_1.loadSpidStrategy(newConfig || this.config);
            if (newConfig) {
                // tslint:disable-next-line: no-object-mutation
                this.config = newConfig;
            }
            passport.unuse("spid");
            // tslint:disable-next-line: no-any
            // Remove login route from Express router stack
            // tslint:disable-next-line: no-object-mutation
            this.app._router.stack = this.app._router.stack.filter(function_1.not(express_1.matchRoute(this.loginPath, "get")));
            this.registerLoginRoute(newSpidStrategy);
            logger_1.log.info("Spid strategy re-initialization complete.");
            return newSpidStrategy;
        }
        catch (err) {
            logger_1.log.error("Error on update spid strategy: %s", err);
            throw exports.SPID_RELOAD_ERROR;
        }
    }
    registerLoginRoute(spidStrategy) {
        passport.use("spid", spidStrategy);
        const spidAuth = passport.authenticate("spid", { session: false });
        this.app.get(this.loginPath, spidAuth);
    }
}
exports.SpidPassportBuilder = SpidPassportBuilder;
//# sourceMappingURL=index.js.map