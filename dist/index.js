"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const function_1 = require("fp-ts/lib/function");
const Option_1 = require("fp-ts/lib/Option");
const responses_1 = require("italia-ts-commons/lib/responses");
const passport = require("passport");
const spidStrategy_1 = require("./strategies/spidStrategy");
exports.SamlAttribute = spidStrategy_1.SamlAttribute;
const spidLevel_1 = require("./types/spidLevel");
exports.isSpidL = spidLevel_1.isSpidL;
exports.SpidLevel = spidLevel_1.SpidLevel;
exports.SpidLevelEnum = spidLevel_1.SpidLevelEnum;
const express_1 = require("./utils/express");
const logger_1 = require("./utils/logger");
const response_1 = require("./utils/response");
exports.getAuthnContextFromResponse = response_1.getAuthnContextFromResponse;
exports.getErrorCodeFromResponse = response_1.getErrorCodeFromResponse;
const saml_1 = require("./utils/saml");
exports.SPID_RELOAD_ERROR = new Error("Error while initializing SPID strategy");
exports.SPID_STRATEGY_NOT_DEFINED = new Error("Spid Strategy not defined.");
class SpidPassportBuilder {
    constructor(app, loginPath, sloPath, assertionConsumerServicePath, metadataPath, config) {
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
    async init(authenticationController, clientErrorRedirectionUrl, clientLoginRedirectionUrl) {
        // tslint:disable-next-line: no-object-mutation
        this.spidStrategy = await spidStrategy_1.loadSpidStrategy(this.config);
        this.registerLoginRoute(this.spidStrategy);
        this.registerAuthRoutes(authenticationController, clientErrorRedirectionUrl, clientLoginRedirectionUrl);
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
            // tslint:disable-next-line: no-object-mutation
            this.metadataXml = undefined;
            this.registerLoginRoute(newSpidStrategy);
            logger_1.log.info("Spid strategy re-initialization complete.");
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
        this.app.get(this.metadataPath, this.toExpressHandler(this.metadata, this));
    }
    registerAuthRoutes(acsController, clientErrorRedirectionUrl, clientLoginRedirectionUrl) {
        this.app.post(this.assertionConsumerServicePath, this.withSpidAuth(acsController, clientErrorRedirectionUrl, clientLoginRedirectionUrl));
        this.app.post(this.sloPath, this.toExpressHandler(acsController.slo, acsController));
    }
    /**
     * Catch SPID authentication errors and redirect the client to
     * clientErrorRedirectionUrl.
     */
    withSpidAuth(controller, clientErrorRedirectionUrl, clientLoginRedirectionUrl) {
        return (req, res, next) => {
            passport.authenticate("spid", async (err, user) => {
                const issuer = saml_1.getSamlIssuer(req.body);
                if (err) {
                    logger_1.log.error("Spid Authentication|Authentication Error|ERROR=%s|ISSUER=%s", err, issuer);
                    return res.redirect(clientErrorRedirectionUrl +
                        Option_1.fromNullable(err.statusXml)
                            .chain(statusXml => response_1.getErrorCodeFromResponse(statusXml))
                            .map(errorCode => `?errorCode=${errorCode}`)
                            .getOrElse(""));
                }
                if (!user) {
                    logger_1.log.error("Spid Authentication|Authentication Error|ERROR=user_not_found|ISSUER=%s", issuer);
                    return res.redirect(clientLoginRedirectionUrl);
                }
                const response = await controller.acs(user);
                response.apply(res);
            })(req, res, next);
        };
    }
    toExpressHandler(handler, object) {
        return (req, res) => handler
            .call(object, req)
            .catch(responses_1.ResponseErrorInternal)
            .then(response => {
            // tslint:disable-next-line:no-object-mutation
            res.locals.detail = response.detail;
            response.apply(res);
        });
    }
    /**
     * The metadata for this Service Provider.
     */
    async metadata() {
        if (this.spidStrategy === undefined) {
            return Promise.reject(exports.SPID_STRATEGY_NOT_DEFINED);
        }
        if (this.metadataXml === undefined) {
            // tslint:disable-next-line: no-object-mutation
            this.metadataXml = this.spidStrategy.generateServiceProviderMetadata(this.config.samlCert);
        }
        return responses_1.ResponseSuccessXml(this.metadataXml);
    }
}
exports.SpidPassportBuilder = SpidPassportBuilder;
//# sourceMappingURL=index.js.map