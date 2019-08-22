import * as t from "io-ts";
import { NonEmptyString } from "italia-ts-commons/lib/strings";
//
import { EmailString } from "italia-ts-commons/lib/strings";
import { FiscalCode } from "italia-ts-commons/lib/strings";
import { SpidLevel } from "../types/spidLevel";

import { Issuer } from "./issuer";

export const SpidUser = t.intersection([
  t.interface({
    authnContextClassRef: SpidLevel,
    getAssertionXml: t.Function,
    issuer: Issuer
  }),
  t.partial({
    email: EmailString,
    familyName: t.string,
    fiscalNumber: FiscalCode,
    mobilePhone: NonEmptyString,
    name: t.string,
    nameID: t.string,
    nameIDFormat: t.string,
    sessionIndex: t.string
  })
]);

export type SpidUser = t.TypeOf<typeof SpidUser>;
