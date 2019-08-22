/**
 * SPID authentication level enum and types.
 *
 * @see http://www.agid.gov.it/agenda-digitale/infrastrutture-architetture/spid/percorso-attuazione
 */
import { SpidLevelEnum } from "../../generated/backend/SpidLevel";
declare type SpidLevel1 = typeof SpidLevelEnum["https://www.spid.gov.it/SpidL1"];
declare type SpidLevel2 = typeof SpidLevelEnum["https://www.spid.gov.it/SpidL2"];
declare type SpidLevel3 = typeof SpidLevelEnum["https://www.spid.gov.it/SpidL3"];
declare type SpidLevel = SpidLevel1 | SpidLevel2 | SpidLevel3;
export declare function isSpidL(uri: string): uri is SpidLevel;
export {};
