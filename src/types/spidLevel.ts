/**
 * SPID authentication level enum and types.
 *
 * @see http://www.agid.gov.it/agenda-digitale/infrastrutture-architetture/spid/percorso-attuazione
 */

import * as t from "io-ts";
import { enumType } from "italia-ts-commons/lib/types";

// tslint:disable: no-duplicate-string

export enum SpidLevelEnum {
  "https://www.spid.gov.it/SpidL1" = "https://www.spid.gov.it/SpidL1",

  "https://www.spid.gov.it/SpidL2" = "https://www.spid.gov.it/SpidL2",

  "https://www.spid.gov.it/SpidL3" = "https://www.spid.gov.it/SpidL3"
}

export type SpidLevel = t.TypeOf<typeof SpidLevel>;
export const SpidLevel = enumType<SpidLevelEnum>(SpidLevelEnum, "SpidLevel");

type SpidLevel1 = typeof SpidLevelEnum["https://www.spid.gov.it/SpidL1"];
type SpidLevel2 = typeof SpidLevelEnum["https://www.spid.gov.it/SpidL2"];
type SpidLevel3 = typeof SpidLevelEnum["https://www.spid.gov.it/SpidL3"];

function isSpidL1(uri: string): uri is SpidLevel1 {
  return uri === SpidLevelEnum["https://www.spid.gov.it/SpidL1"];
}

function isSpidL2(uri: string): uri is SpidLevel2 {
  return uri === SpidLevelEnum["https://www.spid.gov.it/SpidL2"];
}

function isSpidL3(uri: string): uri is SpidLevel3 {
  return uri === SpidLevelEnum["https://www.spid.gov.it/SpidL3"];
}

export function isSpidL(
  uri: string
): uri is SpidLevel1 | SpidLevel2 | SpidLevel3 {
  return isSpidL1(uri) || isSpidL2(uri) || isSpidL3(uri);
}
