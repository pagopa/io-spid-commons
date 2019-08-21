import * as t from "io-ts";
import { NonEmptyString } from "italia-ts-commons/lib/strings";
//
import { EmailAddress } from "../../generated/backend/EmailAddress";
import { FiscalCode } from "../../generated/backend/FiscalCode";
import { SpidLevel } from "../../generated/backend/SpidLevel";

import { Issuer } from "./issuer";

export const SpidUser = t.intersection([
  t.interface({
    authnContextClassRef: SpidLevel,
    getAssertionXml: t.Function,
    issuer: Issuer
  }),
  t.partial({
    email: EmailAddress,
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
