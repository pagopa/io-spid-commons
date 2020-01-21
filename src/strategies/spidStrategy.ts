// tslint:disable: no-console
/**
 * SPID Passport strategy.
 */
import { distanceInWordsToNow, isAfter, subDays } from "date-fns";
import { array } from "fp-ts/lib/Array";
import { fromNullable, isNone, isSome } from "fp-ts/lib/Option";
import { taskEither, TaskEither } from "fp-ts/lib/TaskEither";
import { Profile, SamlConfig, VerifiedCallback } from "passport-saml";
// tslint:disable-next-line: no-submodule-imports
import * as MultiSamlStrategy from "passport-saml/multiSamlStrategy";
import * as x509 from "x509";
import getCieIpdOption from "../testIdpConfigs/xx_servizicie_test";
import getSpidTestIpdOption from "../testIdpConfigs/xx_testenv2";
import { IDPEntityDescriptor } from "../types/IDPEntityDescriptor";
import { fetchIdpsMetadata } from "../utils/idpLoader";

export const SAML_USER_ATTRIBUTES = {
  ADDRESS: "address",
  COMPANY_NAME: "companyName",
  DATE_OF_BIRTH: "dateOfBirth",
  DIGITAL_ADDRESS: "digitalAddress",
  EMAIL: "email",
  FAMILY_NAME: "familyName",
  FISCAL_NUMBER: "fiscalNumber",
  GENDER: "gender",
  ID_CARD: "idCard",
  IVA_CODE: "ivaCode",
  MOBILE_PHONE: "mobilePhone",
  NAME: "name",
  PLACE_OF_BIRTH: "placeOfBirth",
  REGISTERED_OFFICE: "registeredOffice",
  SPID_CODE: "spidCode"
};

export const IDP_IDENTIFIERS = {
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

export type SamlAttributeT = keyof typeof SAML_USER_ATTRIBUTES;

export interface ISpidSamlConfig extends SamlConfig {
  // needed only when generating metadata for the
  // AttributeConsumerService
  attributes: {
    attributes: ReadonlyArray<SamlAttributeT>;
    name: string;
  };
}

/*
 * @see https://www.agid.gov.it/sites/default/files/repository_files/regole_tecniche/tabella_attributi_idp.pdf
 */
export interface IServiceProviderConfig {
  spidTestEnvUrl: string;
  IDPMetadataUrl: string;
  requiredAttributes: ReadonlyArray<SamlAttributeT>;
  organization: {
    URL: string;
    displayName: string;
    name: string;
  };
  publicCert: string;
  hasSpidValidatorEnabled: boolean;
}

export interface ISpidStrategyOptions {
  idp: { [key: string]: IDPEntityDescriptor | undefined };
  // tslint:disable-next-line: no-any
  sp: ISpidSamlConfig;
}

export const getLoadSpidStrategyOptions = (
  samlConfig: SamlConfig,
  serviceProviderConfig: IServiceProviderConfig
): (() => TaskEither<Error, ISpidStrategyOptions>) => () => {
  const idpOptionsTasks = [
    fetchIdpsMetadata(serviceProviderConfig.IDPMetadataUrl, IDP_IDENTIFIERS)
  ].concat(
    serviceProviderConfig.hasSpidValidatorEnabled
      ? [
          fetchIdpsMetadata("http://spid-saml-check:8080/metadata.xml", {
            // TODO: must be a configuration param
            // "https://validator.spid.gov.it": "xx_validator"
            "http://localhost:8080": "xx_validator"
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
      logSamlCertExpiration(serviceProviderConfig.publicCert);
      return {
        idp: {
          ...idpOptionsRecord,
          xx_servizicie_test: getCieIpdOption(),
          xx_testenv2: getSpidTestIpdOption(
            serviceProviderConfig.spidTestEnvUrl
          )
        },
        sp: {
          ...samlConfig,
          attributes: {
            attributes: serviceProviderConfig.requiredAttributes,
            name: "Required attributes"
          },
          identifierFormat:
            "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
          organization: serviceProviderConfig.organization,
          signatureAlgorithm: "sha256"
        }
      };
    });
};

const getSamlOptions: MultiSamlStrategy.MultiSamlConfig["getSamlOptions"] = async (
  req,
  done
) => {
  // Get SPID strategy options
  const spidStrategyOptions: ISpidStrategyOptions = await req.app.get(
    "spidStrategyOptions"
  );
  const idps = spidStrategyOptions.idp;

  // extract IDP from request
  return fromNullable(req.query.entityID)
    .map(entityID => {
      const idp = idps[entityID];
      if (idp === undefined) {
        return done(
          Error(
            `SPID cannot find a valid idp in spidOptions for given entityID: ${entityID}`
          )
        );
      }
      return done(null, {
        ...spidStrategyOptions.sp,
        cert: idp.cert.toArray(),
        entryPoint: idp.entryPoint
      });
    })
    .getOrElseL(() =>
      // check against all memorized certificates
      done(null, {
        ...spidStrategyOptions.sp,
        cert: Object.keys(idps).reduce(
          (prev, k) => [
            ...prev,
            ...(idps[k] && idps[k]!.cert ? idps[k]!.cert.toArray() : [])
          ],
          // tslint:disable-next-line: readonly-array
          [] as string[]
        )
      })
    );
};

export const makeSpidStrategy = (options: ISpidStrategyOptions) => {
  return new MultiSamlStrategy(
    { ...options, getSamlOptions },
    (profile: Profile, done: VerifiedCallback) => {
      console.log(profile.getAssertionXml());
      console.log("logged", JSON.stringify(profile));
      done(null, profile);
    }
  );
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
        console.log("samlCert expire in %s", timeDiff);
      } else if (isAfter(out.notAfter, new Date())) {
        console.warn("samlCert expire in %s", timeDiff);
      } else {
        console.error("samlCert expired from %s", timeDiff);
      }
    } else {
      console.error("Missing expiration date on saml certificate.");
    }
  } catch (e) {
    console.error("Error calculating saml cert expiration: %s", e);
  }
}
