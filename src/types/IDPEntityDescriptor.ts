import * as t from "io-ts";
// tslint:disable-next-line: no-submodule-imports
import { createNonEmptyArrayFromArray } from "io-ts-types/lib/fp-ts/createNonEmptyArrayFromArray";
import { NonEmptyString } from "italia-ts-commons/lib/strings";

export const IDPEntityDescriptor = t.intersection([
  t.interface({
    cert: createNonEmptyArrayFromArray(NonEmptyString),

    entityID: t.string,

    entryPoint: t.string,

    logoutUrl: t.string
  }),
  t.partial({
    attributes: t.array(t.string),
    skipIssuerFormatValidation: t.boolean
  })
]);

export type IDPEntityDescriptor = t.TypeOf<typeof IDPEntityDescriptor>;
