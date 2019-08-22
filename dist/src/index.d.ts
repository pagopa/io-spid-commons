import { Express } from "express";
import { IIoSpidStrategy, ISpidStrategyConfig } from "./strategies/spidStrategy";
export declare const SPID_RELOAD_ERROR: Error;
export declare class SpidPassportBuilder {
    spidStrategy?: IIoSpidStrategy;
    private loginPath;
    private config;
    private app;
    constructor(app: Express, path: string, config: ISpidStrategyConfig);
    /**
     * Initializes SpidStrategy for passport and setup login route.
     */
    init(): Promise<void>;
    clearAndReloadSpidStrategy(newConfig?: ISpidStrategyConfig): Promise<IIoSpidStrategy>;
    private registerLoginRoute;
}
