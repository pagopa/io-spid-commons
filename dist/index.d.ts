import { Express } from "express";
import { IResponseErrorInternal, IResponseErrorValidation, IResponsePermanentRedirect } from "italia-ts-commons/lib/responses";
import { IIoSpidStrategy, ISpidStrategyConfig, SamlAttribute } from "./strategies/spidStrategy";
import { isSpidL, SpidLevel, SpidLevelEnum } from "./types/spidLevel";
import { getAuthnContextFromResponse, getErrorCodeFromResponse } from "./utils/response";
export declare const SPID_RELOAD_ERROR: Error;
export declare const SPID_STRATEGY_NOT_DEFINED: Error;
export interface IAuthenticationController {
    acs: (userPayload: unknown) => Promise<IResponseErrorInternal | IResponseErrorValidation | IResponsePermanentRedirect>;
    slo: () => Promise<IResponsePermanentRedirect>;
}
export { getAuthnContextFromResponse, getErrorCodeFromResponse, isSpidL, IIoSpidStrategy, ISpidStrategyConfig, SamlAttribute, SpidLevel, SpidLevelEnum };
export declare class SpidPassportBuilder {
    private spidStrategy?;
    private loginPath;
    private sloPath;
    private assertionConsumerServicePath;
    private metadataPath;
    private metadataXml?;
    private config;
    private app;
    constructor(app: Express, loginPath: string, sloPath: string, assertionConsumerServicePath: string, metadataPath: string, config: ISpidStrategyConfig);
    /**
     * Initializes SpidStrategy for passport and setup login and auth routes.
     */
    init(authenticationController: IAuthenticationController, clientErrorRedirectionUrl: string, clientLoginRedirectionUrl: string): Promise<void>;
    clearAndReloadSpidStrategy(newConfig?: ISpidStrategyConfig): Promise<void>;
    private registerLoginRoute;
    private registerAuthRoutes;
    /**
     * Catch SPID authentication errors and redirect the client to
     * clientErrorRedirectionUrl.
     */
    private withSpidAuth;
    private toExpressHandler;
    /**
     * The metadata for this Service Provider.
     */
    private metadata;
}
