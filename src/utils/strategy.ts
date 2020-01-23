import { distanceInWordsToNow, isAfter, subDays } from "date-fns";
import { Request as ExpressRequest } from "express";
import { flatten } from "fp-ts/lib/Array";
import { toError } from "fp-ts/lib/Either";
import { fromNullable, isNone, none, Option, some } from "fp-ts/lib/Option";
import { collect, lookup, mapWithKey } from "fp-ts/lib/Record";
import { taskify, tryCatch } from "fp-ts/lib/TaskEither";
import produce from "immer";
import { NonEmptyString } from "italia-ts-commons/lib/strings";
import { SamlConfig } from "passport-saml";
// tslint:disable-next-line: no-submodule-imports
import * as MultiSamlStrategy from "passport-saml/multiSamlStrategy";
import * as x509 from "x509";
import * as xmlCrypto from "xml-crypto";
import { Builder, parseStringPromise } from "xml2js";
import {
  IServiceProviderConfig,
  ISpidStrategyOptions
} from "../strategies/spidStrategy";
import { logger } from "./logger";

export const SPID_USER_ATTRIBUTES = {
  address: "Indirizzo",
  companyName: "Nome azienda",
  dateOfBirth: "Data di nascita",
  digitalAddress: "Indirizzo elettronico",
  email: "Email",
  familyName: "Cognome",
  fiscalNumber: "Codice fiscale",
  gender: "Sesso",
  idCard: "Numero carta di identità",
  ivaCode: "Codice IVA",
  mobilePhone: "Numero di telefono",
  name: "Nome",
  placeOfBirth: "Luogo di nascita",
  registeredOffice: "Ufficio",
  spidCode: "Codice SPID"
};

export const SPID_IDP_IDENTIFIERS = {
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

export type SamlAttributeT = keyof typeof SPID_USER_ATTRIBUTES;

const SPID_LEVELS = {
  SpidL1: "https://www.spid.gov.it/SpidL1",
  SpidL2: "https://www.spid.gov.it/SpidL2",
  SpidL3: "https://www.spid.gov.it/SpidL3"
};

const SPID_URLS = {
  "https://www.spid.gov.it/SpidL1": "SpidL1",
  "https://www.spid.gov.it/SpidL2": "SpidL2",
  "https://www.spid.gov.it/SpidL3": "SpidL3"
};

interface IEntrypointCerts {
  // tslint:disable-next-line: readonly-array
  cert: NonEmptyString[];
  entryPoint?: string;
}

const decodeBase64 = (s: string) => {
  return new Buffer(s, "base64").toString("utf8");
};

const cleanCert = (cert: string) =>
  cert
    .replace(/-+BEGIN CERTIFICATE-+\r?\n?/, "")
    .replace(/-+END CERTIFICATE-+\r?\n?/, "")
    .replace(/\r\n/g, "\n");

/**
 * Extracts IDP entityID from query parameter (if any).
 *
 * @returns
 *  - the certificates (and entrypoint) for the IDP that matches the provided entityID
 *  - all IDP certificates if no entityID is provided (and no entrypoint)
 *  - none if no IDP matches the provided entityID
 */
const getEntrypointCerts = (
  req: ExpressRequest,
  idps: ISpidStrategyOptions["idp"]
): Option<IEntrypointCerts> => {
  return fromNullable(req)
    .mapNullable(r => r.query)
    .mapNullable(q => q.entityID)
    .chain(entityID =>
      fromNullable(idps[entityID]).map(
        idp =>
          ({
            cert: idp.cert.toArray(),
            entryPoint: idp.entryPoint
          } as IEntrypointCerts)
      )
    )
    .alt(
      some({
        cert: flatten(
          collect(idps, (_, idp) => (idp && idp.cert ? idp.cert.toArray() : []))
        ),
        // TODO: leave entryPoint undefined when this gets fixed
        // @see https://github.com/bergie/passport-saml/issues/415
        entryPoint: ""
      } as IEntrypointCerts)
    );
};

const getAuthnContextValueFromResponse = (response: string): Option<string> => {
  const xmlResponse = new DOMParser().parseFromString(response, "text/xml");
  // ie. <saml2:AuthnContextClassRef>https://www.spid.gov.it/SpidL2</saml2:AuthnContextClassRef>
  const responseAuthLevelEl = xmlResponse.getElementsByTagNameNS(
    "urn:oasis:names:tc:SAML:2.0:assertion",
    "AuthnContextClassRef"
  );
  return responseAuthLevelEl[0] && responseAuthLevelEl[0].textContent
    ? some(responseAuthLevelEl[0].textContent.trim())
    : none;
};

const getAuthSalmOptions = (
  req: ExpressRequest,
  decodedResponse?: string
): Option<Partial<SamlConfig>> => {
  return fromNullable(req)
    .mapNullable(r => r.query)
    .mapNullable(q => q.authLevel)
    .chain((authLevel: string) =>
      lookup(authLevel, SPID_LEVELS)
        .map(authnContext => ({
          authnContext,
          forceAuthn: authLevel !== "SpidL1"
        }))
        .orElse(() => {
          logger.error(
            "SPID cannot find a valid authnContext for given authLevel: %s",
            authLevel
          );
          return none;
        })
    )
    .alt(
      fromNullable(decodedResponse)
        .chain(response => getAuthnContextValueFromResponse(response))
        .chain(authnContext =>
          lookup(authnContext, SPID_URLS)
            // check if the parsed value is a valid SPID AuthLevel
            .map(authLevel => {
              return {
                authnContext,
                forceAuthn: authLevel !== "SpidL1"
              };
            })
            .orElse(() => {
              logger.error(
                "SPID cannot find a valid authLevel for given authnContext: %s",
                authnContext
              );
              return none;
            })
        )
    );
};

const logSpidRequest = (req: ExpressRequest, decodedResponse?: string) => {
  // Since authenticate function handles GET and POST requests we log request body
  // (it should contain SAMLResponse) for POST requests, for GET cases we log entityID and authLevel
  if (req.method === "POST") {
    logger.debug("SPID raw POST request: %s\n", JSON.stringify(req.body));
  } else if (req.method === "GET") {
    logger.debug(
      "SPID GET request entityID: %s - authLevel: %s\n",
      req.query.entityID,
      req.query.authLevel
    );
  } else {
    logger.debug("SPID request method: %s\n", req.method);
  }
  if (decodedResponse && req.method === "POST") {
    logger.debug("SPID decoded POST request: %s\n", decodedResponse);
  }
};

/**
 * Reads dates information in x509 certificate and logs remaining time to its expiration date.
 * @param samlCert x509 certificate as string
 */
export function logSamlCertExpiration(samlCert: string): void {
  try {
    const out = x509.parseCert(samlCert);
    if (out.notAfter) {
      const timeDiff = distanceInWordsToNow(out.notAfter);
      const warningDate = subDays(new Date(), 60);
      if (isAfter(out.notAfter, warningDate)) {
        logger.info("samlCert expire in %s", timeDiff);
      } else if (isAfter(out.notAfter, new Date())) {
        logger.warn("samlCert expire in %s", timeDiff);
      } else {
        logger.error("samlCert expired from %s", timeDiff);
      }
    } else {
      logger.error("Missing expiration date on saml certificate.");
    }
  } catch (e) {
    logger.error("Error calculating saml cert expiration: %s", e);
  }
}

export const getSamlOptions: MultiSamlStrategy.MultiSamlConfig["getSamlOptions"] = async (
  req,
  done
) => {
  // Get decoded response
  const decodedResponse =
    req.body && req.body.SAMLResponse
      ? decodeBase64(req.body.SAMLResponse)
      : undefined;

  logSpidRequest(req, decodedResponse);

  // Get SPID strategy options
  const spidStrategyOptions: ISpidStrategyOptions = await req.app.get(
    "spidStrategyOptions"
  );

  const maybeEntrypointCerts = getEntrypointCerts(req, spidStrategyOptions.idp);
  if (isNone(maybeEntrypointCerts)) {
    logger.debug(
      `SPID cannot find a valid idp in spidOptions for given entityID: ${req.query.entityID}`
    );
  }
  const entrypointCerts = maybeEntrypointCerts.getOrElse(
    {} as IEntrypointCerts
  );

  const maybeAuthOptions = getAuthSalmOptions(req, decodedResponse);
  if (isNone(maybeAuthOptions)) {
    logger.debug(
      "SPID cannot find authnContext in response %s",
      decodedResponse
    );
  }
  const authOptions = maybeAuthOptions.getOrElse({});

  return done(null, {
    ...spidStrategyOptions.sp,
    ...entrypointCerts,
    ...authOptions
  });
};

const getSpidAttributesMetadata = (
  serviceProviderConfig: IServiceProviderConfig
) => {
  return serviceProviderConfig.requiredAttributes
    ? serviceProviderConfig.requiredAttributes.attributes.map(item => ({
        $: {
          FriendlyName: SPID_USER_ATTRIBUTES[item],
          Name: item,
          NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
        }
      }))
    : [];
};

const getSpidOrganizationMetadata = (
  serviceProviderConfig: IServiceProviderConfig
) => {
  return serviceProviderConfig.organization
    ? {
        Organization: {
          OrganizationName: {
            $: { "xml:lang": "it" },
            _: serviceProviderConfig.organization.name
          },
          // must appear after organization name
          // tslint:disable-next-line: object-literal-sort-keys
          OrganizationDisplayName: {
            $: { "xml:lang": "it" },
            _: serviceProviderConfig.organization.displayName
          },
          OrganizationURL: {
            $: { "xml:lang": "it" },
            _: serviceProviderConfig.organization.URL
          }
        }
      }
    : {};
};

const getKeyInfoForMetadata = (publicCert: string, privateKey: string) => ({
  file: privateKey,
  getKey: () => Buffer.from(privateKey),
  getKeyInfo: () =>
    `<X509Data><X509Certificate>${publicCert}</X509Certificate></X509Data>`
});

const generateServiceProviderMetadataTask = (spidStrategy: MultiSamlStrategy) =>
  taskify(spidStrategy.generateServiceProviderMetadata.bind(spidStrategy));

const xmlBuilder = new Builder();

export const getServiceProviderMetadata = (
  spidStrategy: MultiSamlStrategy,
  serviceProviderConfig: IServiceProviderConfig,
  samlConfig: SamlConfig,
  req: ExpressRequest
) => {
  return generateServiceProviderMetadataTask(spidStrategy)(
    req,
    null, // decryptionCert = public cert that matches the private decryptionPvk key
    serviceProviderConfig.publicCert // signingCert = public cert that matches the privateCert key
  )
    .chain(generateXml =>
      tryCatch(() => parseStringPromise(generateXml), toError)
    )
    .chain(objXml => {
      return tryCatch(
        async () =>
          // tslint:disable-next-line: no-any
          produce(objXml, (o: any) => {
            console.log(JSON.stringify(o, null, 2));
            const sso = o.EntityDescriptor.SPSSODescriptor[0];
            // tslint:disable-next-line: no-object-mutation
            sso.$ = {
              ...sso.$,
              AuthnRequestsSigned: true,
              WantAssertionsSigned: true
            };
            // tslint:disable-next-line: no-object-mutation
            sso.AssertionConsumerService[0].$.index = 0;
            // tslint:disable-next-line: no-object-mutation
            sso.AttributeConsumingService = {
              $: {
                index: samlConfig.attributeConsumingServiceIndex
              },
              ServiceName: {
                $: {
                  "xml:lang": "it"
                },
                _: serviceProviderConfig.requiredAttributes.name
              },
              // must appear after attributes
              // tslint:disable-next-line: object-literal-sort-keys
              RequestedAttribute: getSpidAttributesMetadata(
                serviceProviderConfig
              )
            };
            // tslint:disable-next-line: no-object-mutation
            o.EntityDescriptor = {
              ...o.EntityDescriptor,
              ...getSpidOrganizationMetadata(serviceProviderConfig)
            };
          }),
        toError
      );
    })
    .chain(_ => tryCatch(async () => xmlBuilder.buildObject(_), toError))
    .chain(xml =>
      tryCatch(async () => {
        if (!samlConfig.privateCert) {
          throw new Error(
            "You must provide a private key to sign SPID service provider metadata."
          );
        }
        const sig = new xmlCrypto.SignedXml();
        const publicCert = cleanCert(serviceProviderConfig.publicCert);
        // tslint:disable-next-line: no-object-mutation
        sig.keyInfoProvider = getKeyInfoForMetadata(
          publicCert,
          samlConfig.privateCert
        );
        // tslint:disable-next-line: no-object-mutation
        sig.signatureAlgorithm =
          "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        // tslint:disable-next-line: no-object-mutation
        sig.signingKey = samlConfig.privateCert;
        sig.addReference(
          "//*[local-name(.)='EntityDescriptor']",
          [
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/2001/10/xml-exc-c14n#"
          ],
          "http://www.w3.org/2001/04/xmlenc#sha256"
        );
        sig.computeSignature(xml, {
          // Place the signature tag before all other tags
          location: { reference: "", action: "prepend" }
        });
        return sig.getSignedXml();
      }, toError)
    )
    .map(_ => {
      console.log(_);
      return _;
    });
};
