// tslint:disable-next-line: no-submodule-imports
import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import * as t from "io-ts";
// tslint:disable-next-line: no-submodule-imports
import { nonEmptyArray as createNonEmptyArrayFromArray } from "io-ts-types/nonEmptyArray";

export const IDPEntityDescriptor = t.interface({
  cert: createNonEmptyArrayFromArray(NonEmptyString),

  entityID: t.string,

  entryPoint: t.string,

  logoutUrl: t.string
});

export type IDPEntityDescriptor = t.TypeOf<typeof IDPEntityDescriptor>;
