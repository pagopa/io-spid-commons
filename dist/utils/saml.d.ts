import * as t from "io-ts";
declare const SAMLResponse: t.TypeC<{
    SAMLResponse: t.StringC;
}>;
export declare type SAMLResponse = t.TypeOf<typeof SAMLResponse>;
export declare const getSamlIssuer: (body: unknown) => string;
export {};
