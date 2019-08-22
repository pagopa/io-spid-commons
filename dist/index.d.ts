import { Express } from "express";
import { IIoSpidStrategy, ISpidStrategyConfig, SamlAttribute } from "./strategies/spidStrategy";
import { isSpidL, SpidLevel } from "./types/spidLevel";
export declare const SPID_RELOAD_ERROR: Error;
export declare const SPID_STRATEGY_NOT_DEFINED: Error;
export { isSpidL, IIoSpidStrategy, ISpidStrategyConfig, SamlAttribute, SpidLevel };
export declare class SpidPassportBuilder {
    private spidStrategy?;
    private loginPath;
    private metadataPath;
    private metadataXml?;
    private config;
    private app;
    constructor(app: Express, loginPath: string, metadataPath: string, config: ISpidStrategyConfig);
    /**
     * Initializes SpidStrategy for passport and setup login route.
     */
    init(): Promise<void>;
    clearAndReloadSpidStrategy(newConfig?: ISpidStrategyConfig): Promise<void>;
    private registerLoginRoute;
    private toExpressHandler;
    /**
     * The metadata for this Service Provider.
     */
    private metadata;
}
