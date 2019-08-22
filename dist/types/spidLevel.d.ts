/**
 * SPID authentication level enum and types.
 *
 * @see http://www.agid.gov.it/agenda-digitale/infrastrutture-architetture/spid/percorso-attuazione
 */
import * as t from "io-ts";
export declare enum SpidLevelEnum {
    "https://www.spid.gov.it/SpidL1" = "https://www.spid.gov.it/SpidL1",
    "https://www.spid.gov.it/SpidL2" = "https://www.spid.gov.it/SpidL2",
    "https://www.spid.gov.it/SpidL3" = "https://www.spid.gov.it/SpidL3"
}
export declare type SpidLevel = t.TypeOf<typeof SpidLevel>;
export declare const SpidLevel: t.Type<SpidLevelEnum, SpidLevelEnum, unknown>;
declare type SpidLevel1 = typeof SpidLevelEnum["https://www.spid.gov.it/SpidL1"];
declare type SpidLevel2 = typeof SpidLevelEnum["https://www.spid.gov.it/SpidL2"];
declare type SpidLevel3 = typeof SpidLevelEnum["https://www.spid.gov.it/SpidL3"];
export declare function isSpidL(uri: string): uri is SpidLevel1 | SpidLevel2 | SpidLevel3;
export {};
