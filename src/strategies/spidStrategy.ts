/**
 * Builds and configure a Passport strategy to authenticate the proxy to the
 * different SPID IDPs.
 */
import { distanceInWordsToNow, isAfter, subDays } from "date-fns";
import { array } from "fp-ts/lib/Array";
import { toError } from "fp-ts/lib/Either";
import {
  fromEither,
  fromPredicate,
  taskEither,
  TaskEither,
  tryCatch
} from "fp-ts/lib/TaskEither";
import { Strategy } from "passport";
import * as SpidStrategy from "spid-passport";
import * as x509 from "x509";
import getCieIpdOption from "../testIdpConfigs/xx_servizicie_test";
import getSpidTestIpdOption from "../testIdpConfigs/xx_testenv2";
import { SpidUser } from "../types/spidUser";
import {
  fetchIdpMetadata,
  IDPOption,
  mapIpdMetadata,
  parseIdpMetadata
} from "../utils/idpLoader";
import { log } from "../utils/logger";

export const IDP_IDS: Record<string, string> = {
  "https://id.lepida.it/idp/shibboleth": "lepidaid",
  "https://identity.infocert.it": "infocertid",
  "https://identity.sieltecloud.it": "sielteid",
  "https://idp.namirialtsp.com/idp": "namirialid",
  "https://login.id.tim.it/affwebservices/public/saml2sso": "timid",
  "https://loginspid.aruba.it": "arubaid",
  "https://posteid.poste.it": "posteid",
  "https://spid.intesa.it": "intesaid",
  "https://spid.register.it": "spiditalia"
};

export interface IIoSpidStrategy extends Strategy {
  spidOptions: {
    idp: { [key: string]: IDPOption | undefined };
    // tslint:disable-next-line: no-any
    sp: any;
  };
  // tslint:disable-next-line:no-any
  logout: (req: any, callback?: (err: any, request: any) => void) => void;
  generateServiceProviderMetadata: (samlCert: string) => string;
}

/**
 * Load idp Metadata from a remote url, parse infos and return a mapped and whitelisted idp options
 * for spidStrategy object.
 */
export function loadFromRemote(
  idpMetadataUrl: string,
  idpIds: Record<string, string>
): TaskEither<Error, Record<string, IDPOption>> {
  return tryCatch(() => {
    log.info("Fetching SPID metadata from [%s]...", idpMetadataUrl);
    return fetchIdpMetadata(idpMetadataUrl);
  }, toError)
    .chain(idpMetadataXML => {
      log.info("Parsing SPID metadata...");
      return fromEither(parseIdpMetadata(idpMetadataXML));
    })
    .chain(
      fromPredicate(
        idpMetadata => idpMetadata.length > 0,
        () => {
          log.error("No SPID metadata found from the url: %s", idpMetadataUrl);
          return new Error("No SPID metadata found");
        }
      )
    )
    .map(idpMetadata => {
      if (idpMetadata.length < Object.keys(idpIds).length) {
        log.warn("Missing SPID metadata on [%s]", idpMetadataUrl);
      }
      log.info("Configuring IdPs...");
      return mapIpdMetadata(idpMetadata, idpIds);
    });
}

/*
 * @see https://www.agid.gov.it/sites/default/files/repository_files/regole_tecniche/tabella_attributi_idp.pdf
 */
export enum SamlAttribute {
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
  hasSpidValidatorEnabled: boolean;
}

export const loadSpidStrategy = (
  config: ISpidStrategyConfig
): TaskEither<Error, IIoSpidStrategy> => {
  const idpOptionsTasks = [
    loadFromRemote(config.IDPMetadataUrl, IDP_IDS)
  ].concat(
    config.hasSpidValidatorEnabled
      ? [
          loadFromRemote("https://validator.spid.gov.it/metadata.xml", {
            "https://validator.spid.gov.it": "xx_validator"
          })
        ]
      : []
  );
  return array
    .sequence(taskEither)(idpOptionsTasks)
    .map(idpOptionsRecords =>
      idpOptionsRecords.reduce((prev, current) => ({ ...prev, ...current }), {})
    )
    .map(idpOptionsRecord => {
      logSamlCertExpiration(config.samlCert);
      const options: {
        idp: { [key: string]: IDPOption | undefined };
        // tslint:disable-next-line: no-any
        sp: any;
      } = {
        idp: {
          ...idpOptionsRecord,
          xx_servizicie_test: getCieIpdOption(),
          xx_testenv2: getSpidTestIpdOption(config.spidTestEnvUrl)
        },
        sp: {
          acceptedClockSkewMs: config.samlAcceptedClockSkewMs,
          attributeConsumingServiceIndex:
            config.samlAttributeConsumingServiceIndex,
          attributes: {
            attributes: config.requiredAttributes,
            name: "Required attributes"
          },
          callbackUrl: config.samlCallbackUrl,
          decryptionPvk: config.samlKey,
          identifierFormat:
            "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
          issuer: config.samlIssuer,
          organization: config.organization,
          privateCert: config.samlKey,
          signatureAlgorithm: "sha256"
        }
      };
      const optionsWithAutoLoginInfo = {
        ...options,
        sp: {
          ...options.sp,
          additionalParams: {
            auto_login: config.spidAutologin
          }
        }
      };
      return new SpidStrategy(
        config.spidAutologin === "" ? options : optionsWithAutoLoginInfo,
        (
          profile: SpidUser,
          done: (err: Error | undefined, info: SpidUser) => void
        ) => {
          log.info(profile.getAssertionXml());
          done(undefined, profile);
        }
      ) as IIoSpidStrategy;
    });
};

/**
 * Reads dates information in x509 certificate and logs remaining time to its expiration date.
 * @param samlCert x509 certificate as string
 */
function logSamlCertExpiration(samlCert: string): void {
  try {
    const out = x509.parseCert(samlCert);
    if (out.notAfter) {
      const timeDiff = distanceInWordsToNow(out.notAfter);
      const warningDate = subDays(new Date(), 60);
      if (isAfter(out.notAfter, warningDate)) {
        log.info("samlCert expire in %s", timeDiff);
      } else if (isAfter(out.notAfter, new Date())) {
        log.warn("samlCert expire in %s", timeDiff);
      } else {
        log.error("samlCert expired from %s", timeDiff);
      }
    } else {
      log.error("Missing expiration date on saml certificate.");
    }
  } catch (e) {
    log.error("Error calculating saml cert expiration: %s", e);
  }
}
