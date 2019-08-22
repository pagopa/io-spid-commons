import * as t from "io-ts";
export declare const SpidUser: t.IntersectionC<[t.TypeC<{
    authnContextClassRef: t.Type<import("./spidLevel").SpidLevelEnum, import("./spidLevel").SpidLevelEnum, unknown>;
    getAssertionXml: t.FunctionC;
    issuer: t.TypeC<{
        _: t.StringC;
    }>;
}>, t.PartialC<{
    email: t.Type<string & import("italia-ts-commons/lib/strings").IEmailStringTag, string & import("italia-ts-commons/lib/strings").IEmailStringTag, unknown>;
    familyName: t.StringC;
    fiscalNumber: t.Type<string & import("italia-ts-commons/lib/strings").IPatternStringTag<"^[A-Z]{6}[0-9LMNPQRSTUV]{2}[ABCDEHLMPRST][0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{3}[A-Z]$">, string & import("italia-ts-commons/lib/strings").IPatternStringTag<"^[A-Z]{6}[0-9LMNPQRSTUV]{2}[ABCDEHLMPRST][0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{3}[A-Z]$">, unknown>;
    mobilePhone: t.Type<string & import("italia-ts-commons/lib/strings").INonEmptyStringTag, string & import("italia-ts-commons/lib/strings").INonEmptyStringTag, unknown>;
    name: t.StringC;
    nameID: t.StringC;
    nameIDFormat: t.StringC;
    sessionIndex: t.StringC;
}>]>;
export declare type SpidUser = t.TypeOf<typeof SpidUser>;
