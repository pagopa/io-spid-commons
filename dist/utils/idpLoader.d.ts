import { IDPEntityDescriptor } from "../types/IDPEntityDescriptor";
/**
 * Parse a string that represents an XML file containing the ipd Metadata and converts it into an array of IDPEntityDescriptor
 * Required namespace definitions into the XML are xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" and xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
 * An example file is provided in /test_idps/spid-entities-idps.xml of this project.
 */
export declare function parseIdpMetadata(ipdMetadataPage: string): ReadonlyArray<IDPEntityDescriptor>;
/**
 * Fetch an ipds Metadata XML file from a remote url and convert it into a string
 */
export declare function fetchIdpMetadata(idpMetadataUrl: string): Promise<string>;
export interface IDPOption {
    cert: string[];
    entityID: string;
    entryPoint: string;
    logoutUrl: string;
}
/**
 * Map provided idpMetadata in an object with idp key whitelisted in ipdIds.
 * Mapping is based on entityID property
 */
export declare const mapIpdMetadata: (idpMetadata: readonly {
    cert: import("fp-ts/lib/NonEmptyArray").NonEmptyArray<string & import("italia-ts-commons/lib/strings").INonEmptyStringTag>;
    entityID: string;
    entryPoint: string;
    logoutUrl: string;
}[], idpIds: Record<string, string>) => Record<string, IDPOption>;
