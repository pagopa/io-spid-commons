import { Strategy } from "passport";
import { IDPOption } from "../utils/idpLoader";
export interface IIoSpidStrategy extends Strategy {
    spidOptions: {
        idp: {
            [key: string]: IDPOption | undefined;
        };
        sp: any;
    };
    logout: (req: any, callback?: (err: any, request: any) => void) => void;
    generateServiceProviderMetadata: (samlCert: string) => string;
}
/**
 * Load idp Metadata from a remote url, parse infomations and return a mapped and whitelisted idp options
 * for spidStrategy object.
 */
export declare function loadFromRemote(idpMetadataUrl: string): Promise<{
    [key: string]: IDPOption | undefined;
}>;
export declare enum SamlAttribute {
    FAMILY_NAME = "familyName",
    NAME = "name",
    SPID_CODE = "spidCode",
    GENDER = "gender",
    FISCAL_NUMBER = "fiscalNumber",
    DATE_OF_BIRTH = "dateOfBirth",
    PLACE_OF_BIRTH = "placeOfBirth",
    COMPANY_NAME = "companyName",
    REGISTERED_OFFICE = "registeredOffice",
    IVA_CODE = "ivaCode",
    ID_CARD = "idCard",
    MOBILE_PHONE = "mobilePhone",
    EMAIL = "email",
    ADDRESS = "address",
    DIGITAL_ADDRESS = "digitalAddress"
}
export interface ISpidStrategyConfig {
    samlKey: string;
    samlCert: string;
    samlCallbackUrl: string;
    samlIssuer: string;
    samlAcceptedClockSkewMs: number;
    samlAttributeConsumingServiceIndex: number;
    spidAutologin: string;
    spidTestEnvUrl: string;
    IDPMetadataUrl: string;
    requiredAttributes: ReadonlyArray<SamlAttribute>;
    organization: {
        URL: string;
        displayName: string;
        name: string;
    };
}
export declare const loadSpidStrategy: (config: ISpidStrategyConfig) => Promise<IIoSpidStrategy>;
