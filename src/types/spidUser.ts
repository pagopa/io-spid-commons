import * as t from "io-ts";
import { NonEmptyString } from "italia-ts-commons/lib/strings";
//
import { EmailString } from "italia-ts-commons/lib/strings";
import { FiscalCode } from "italia-ts-commons/lib/strings";

import { SPID_LEVELS } from "../config";

const Issuer = t.interface({
  _: t.string
});

export const SpidUser = t.intersection([
  t.interface({
    authnContextClassRef: t.keyof(SPID_LEVELS),
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
