import * as t from "io-ts";
export declare const IDPEntityDescriptor: t.TypeC<{
    cert: import("io-ts-types/lib/fp-ts/createNonEmptyArrayFromArray").NonEmptyArrayFromArrayC<t.Type<string & import("italia-ts-commons/lib/strings").INonEmptyStringTag, string & import("italia-ts-commons/lib/strings").INonEmptyStringTag, unknown>>;
    entityID: t.StringC;
    entryPoint: t.StringC;
    logoutUrl: t.StringC;
}>;
export declare type IDPEntityDescriptor = t.TypeOf<typeof IDPEntityDescriptor>;
