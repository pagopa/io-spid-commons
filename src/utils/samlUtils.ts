/**
 * Methods used to tamper passport-saml generated SAML XML.
 *
 * SPID protocol has some peculiarities that need to be addressed
 * to make request, metadata and responses compliant.
 */
import * as jose from "jose";
import { UTCISODateFromString } from "@pagopa/ts-commons/lib/dates";
import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import { distanceInWordsToNow, isAfter, subDays } from "date-fns";
import { Request as ExpressRequest } from "express";
import { predicate as PR } from "fp-ts";
import { flatten } from "fp-ts/lib/Array";
import * as E from "fp-ts/lib/Either";
import { pipe } from "fp-ts/lib/function";
import * as O from "fp-ts/lib/Option";
import { collect, lookup } from "fp-ts/lib/Record";
import { Ord } from "fp-ts/lib/string";
import * as TE from "fp-ts/lib/TaskEither";
import * as t from "io-ts";
import { pki } from "node-forge";
import { SamlConfig } from "passport-saml";
import { MultiSamlConfig } from "passport-saml/multiSamlStrategy";
import * as xmlCrypto from "xml-crypto";
import { Builder, parseStringPromise } from "xml2js";
import { DOMParser } from "xmldom";
import { SPID_LEVELS, SPID_URLS, SPID_USER_ATTRIBUTES } from "../config";
import { EventTracker } from "..";
import {
  DEFAULT_LOLLIPOP_HASH_ALGORITHM,
  ILollipopParams
} from "../types/lollipop";
import { logger } from "./logger";
import {
  ContactType,
  EntityType,
  getSpidStrategyOption,
  IServiceProviderConfig,
  ISpidStrategyOptions
} from "./middleware";
import { IIssueInstantWithAuthnContextCR } from "./saml";

export type SamlAttributeT = keyof typeof SPID_USER_ATTRIBUTES;

interface IEntrypointCerts {
  readonly cert: ReadonlyArray<NonEmptyString>;
  readonly entryPoint?: string;
  readonly idpIssuer?: string;
}

export const SAML_NAMESPACE = {
  ASSERTION: "urn:oasis:names:tc:SAML:2.0:assertion",
  PROTOCOL: "urn:oasis:names:tc:SAML:2.0:protocol",
  SPID: "https://spid.gov.it/saml-extensions",
  XMLDSIG: "http://www.w3.org/2000/09/xmldsig#"
};

export const XML_TAGS = {
  LANG: "xml:lang"
};

export const SPID_TAGS = {
  ENTITY_TYPE: "spid:EntityType",
  FISCAL_CODE: "spid:FiscalCode",
  IPA_CODE: "spid:IPACode",
  VAT_NUMBER: "spid:VATNumber"
};

export const ISSUER_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

const decodeBase64 = (s: string): string =>
  Buffer.from(s, "base64").toString("utf8");

/**
 * Remove prefix and suffix from x509 certificate.
 */
const cleanCert = (cert: string): string =>
  cert
    .replace(/-+BEGIN CERTIFICATE-+\r?\n?/, "")
    .replace(/-+END CERTIFICATE-+\r?\n?/, "")
    .replace(/\r\n/g, "\n");

const SAMLResponse = t.type({
  SAMLResponse: t.string
});

export const InfoNotAvailable = "NOT AVAILABLE";

/**
 * If an eventHandler and a feature flag are provided this function logs the timing deltas.
 * This is useful to monitor the timings and to adjust the clockSkewMs variable
 */
export const extractAndLogTimings = (
  startTime: number,
  idpIssuer: string,
  requestId: string,
  clockSkewMs: number = 0,
  eventHandler?: EventTracker,
  hasClockSkewLoggingEvent?: boolean
  // eslint-disable-next-line max-params
) => (info: IIssueInstantWithAuthnContextCR): TE.TaskEither<never, void> => {
  // when clockSkewMs is set to -1 the validations are always true, so we skip the logs in that case
  if (eventHandler && hasClockSkewLoggingEvent && clockSkewMs !== -1) {
    const extractNotOnOrAfterDelta = (
      element: Element
    ): E.Either<Error, string> =>
      pipe(
        NonEmptyString.decode(element.getAttribute("NotOnOrAfter")),
        E.chain(UTCISODateFromString.decode),
        E.mapLeft(() => new Error("Could not find/convert NotOnOrAfter")),
        E.map(NotOnOrAfter =>
          String(NotOnOrAfter.getTime() - (startTime - clockSkewMs))
        )
      );

    const ResponseIssueInstantClockSkew = String(
      startTime + clockSkewMs - info.IssueInstant.getTime()
    );
    const AssertionIssueInstantClockSkew = String(
      startTime + clockSkewMs - info.AssertionIssueInstant.getTime()
    );
    const AssertionNotBeforeClockSkew = pipe(
      info.Assertion.getAttribute("NotBefore"),
      NonEmptyString.decode,
      E.chain(UTCISODateFromString.decode),
      E.map(NotBefore => String(startTime + clockSkewMs - NotBefore.getTime())),
      E.getOrElseW(() => InfoNotAvailable)
    );
    const AssertionSubjectNotOnOrAfterClockSkew = pipe(
      info.Assertion.getElementsByTagNameNS(
        SAML_NAMESPACE.ASSERTION,
        "Subject"
      ).item(0),
      O.fromNullable,
      O.chainNullableK(Subject =>
        Subject.getElementsByTagNameNS(
          SAML_NAMESPACE.ASSERTION,
          "SubjectConfirmation"
        ).item(0)
      ),
      O.chainNullableK(SubjectConfirmation =>
        SubjectConfirmation.getElementsByTagNameNS(
          SAML_NAMESPACE.ASSERTION,
          "SubjectConfirmationData"
        ).item(0)
      ),
      E.fromOption(() => new Error("Could not find elements")),
      E.chainW(extractNotOnOrAfterDelta),
      E.getOrElseW(() => InfoNotAvailable)
    );
    const AssertionConditionsNotOnOrAfterClockSkew = pipe(
      info.Assertion.getElementsByTagNameNS(
        SAML_NAMESPACE.ASSERTION,
        "Conditions"
      ).item(0),
      O.fromNullable,
      E.fromOption(() => new Error("Could not find elements")),
      E.chainW(extractNotOnOrAfterDelta),
      E.getOrElseW(() => InfoNotAvailable)
    );

    const timings = {
      AssertionConditionsNotOnOrAfterClockSkew,
      AssertionIssueInstantClockSkew,
      AssertionNotBeforeClockSkew,
      AssertionSubjectNotOnOrAfterClockSkew,
      ResponseIssueInstantClockSkew
    };

    eventHandler({
      data: {
        idpIssuer,
        message: "Clockskew validations logging",
        requestId,
        ...timings
      },
      name: "spid.info.clockskew",
      type: "INFO"
    });
  }

  return TE.right(void 0);
};

/**
 * True if the element contains at least one element signed using hamc
 *
 * @param e
 */
const isSignedWithHmac = (e: Element): boolean => {
  const signatures = e.getElementsByTagNameNS(
    SAML_NAMESPACE.XMLDSIG,
    "SignatureMethod"
  );
  return Array.from({ length: signatures.length })
    .map((_, i) => signatures.item(i))
    .some(
      item =>
        item?.getAttribute("Algorithm")?.valueOf() ===
        "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
    );
};

export const notSignedWithHmacPredicate = E.fromPredicate(
  PR.not(isSignedWithHmac),
  _ => new Error("HMAC Signature is forbidden")
);

export const getXmlFromSamlResponse = (body: unknown): O.Option<Document> =>
  pipe(
    O.fromEither(SAMLResponse.decode(body)),
    O.map(_ => decodeBase64(_.SAMLResponse)),
    O.chain(_ => O.tryCatch(() => new DOMParser().parseFromString(_)))
  );

/**
 * Extract StatusMessage from SAML response
 *
 * ie. for <StatusMessage>ErrorCode nr22</StatusMessage>
 * returns "22"
 */
export const getErrorCodeFromResponse = (doc: Document): O.Option<string> =>
  pipe(
    O.fromNullable(
      doc.getElementsByTagNameNS(SAML_NAMESPACE.PROTOCOL, "StatusMessage")
    ),
    O.chain(responseStatusMessageEl =>
      responseStatusMessageEl?.[0]?.textContent
        ? O.some(responseStatusMessageEl[0].textContent.trim())
        : O.none
    ),
    O.chain(errorString => {
      const indexString = "ErrorCode nr";
      const errorCode = errorString.slice(
        errorString.indexOf(indexString) + indexString.length
      );
      return errorCode !== "" ? O.some(errorCode) : O.none;
    })
  );

/**
 * Extracts the issuer field from the response body.
 */
export const getSamlIssuer = (doc: Document): O.Option<string> =>
  pipe(
    O.fromNullable(
      doc.getElementsByTagNameNS(SAML_NAMESPACE.ASSERTION, "Issuer").item(0)
    ),
    O.chainNullableK(_ => _.textContent?.trim())
  );

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
): O.Option<IEntrypointCerts> =>
  pipe(
    O.fromNullable(req),
    O.chainNullableK(r => r.query),
    O.chainNullableK(q => q.entityID),
    O.chain(entityID =>
      // As only strings can be key of an object (other than number and Symbol),
      //  we have to narrow type to have the compiler accept it
      // In the unlikely case entityID is not a string, an empty value is returned
      typeof entityID === "string"
        ? pipe(
            O.fromNullable(idps[entityID]),
            O.map(
              (idp): IEntrypointCerts => ({
                cert: idp.cert,
                entryPoint: idp.entryPoint,
                idpIssuer: idp.entityID
              })
            )
          )
        : O.none
    ),
    O.alt(() =>
      // collect all IDP certificates in case no entityID is provided
      O.some({
        cert: pipe(
          idps,
          collect(Ord)((_, idp) => idp?.cert || []),
          flatten
        ),
        // TODO: leave entryPoint undefined when this gets fixed
        // @see https://github.com/bergie/passport-saml/issues/415
        entryPoint: ""
      } as IEntrypointCerts)
    )
  );

export const getIDFromRequest = (requestXML: string): O.Option<string> => {
  const xmlRequest = new DOMParser().parseFromString(requestXML, "text/xml");
  return pipe(
    O.fromNullable(
      xmlRequest
        .getElementsByTagNameNS(SAML_NAMESPACE.PROTOCOL, "AuthnRequest")
        .item(0)
    ),
    O.chain(AuthnRequest =>
      O.fromEither(NonEmptyString.decode(AuthnRequest.getAttribute("ID")))
    )
  );
};

const getAuthnContextValueFromResponse = (
  response: string
): O.Option<string> => {
  const xmlResponse = new DOMParser().parseFromString(response, "text/xml");
  // ie. <saml2:AuthnContextClassRef>https://www.spid.gov.it/SpidL2</saml2:AuthnContextClassRef>
  const responseAuthLevelEl = xmlResponse.getElementsByTagNameNS(
    SAML_NAMESPACE.ASSERTION,
    "AuthnContextClassRef"
  );
  return responseAuthLevelEl[0]?.textContent
    ? O.some(responseAuthLevelEl[0].textContent.trim())
    : O.none;
};

/**
 * Extracts the correct SPID level from response.
 */
const getAuthSalmOptions = (
  req: ExpressRequest,
  decodedResponse?: string
): O.Option<Partial<SamlConfig>> =>
  pipe(
    O.fromNullable(req),
    O.chainNullableK(r => r.query),
    O.chainNullableK(q => q.authLevel),
    // As only strings can be key of SPID_LEVELS record,
    //  we have to narrow type to have the compiler accept it
    // In the unlikely case authLevel is not a string, an empty value is returned
    O.filter((e): e is string => typeof e === "string"),
    O.chain((authLevel: string) =>
      pipe(
        lookup(authLevel, SPID_LEVELS),
        O.map(authnContext => ({
          authnContext,
          forceAuthn: authLevel !== "SpidL1"
        })),
        O.altW(() => {
          logger.error(
            "SPID cannot find a valid authnContext for given authLevel: %s",
            authLevel
          );
          return O.none;
        })
      )
    ),
    O.alt(() =>
      pipe(
        O.fromNullable(decodedResponse),
        O.chain(response => getAuthnContextValueFromResponse(response)),
        O.chain(authnContext =>
          pipe(
            lookup(authnContext, SPID_URLS),
            // check if the parsed value is a valid SPID AuthLevel
            O.map(authLevel => ({
              authnContext,
              forceAuthn: authLevel !== "SpidL1"
            })),
            O.altW(() => {
              logger.error(
                "SPID cannot find a valid authLevel for given authnContext: %s",
                authnContext
              );
              return O.none;
            })
          )
        )
      )
    )
  );

/**
 * Reads dates information in x509 certificate
 * and logs remaining time to its expiration date.
 *
 * @param samlCert x509 certificate as string
 */
export const logSamlCertExpiration = (samlCert: string): void => {
  try {
    const out = pki.certificateFromPem(samlCert);
    if (out.validity.notAfter) {
      const timeDiff = distanceInWordsToNow(out.validity.notAfter);
      const warningDate = subDays(new Date(), 60);
      if (isAfter(out.validity.notAfter, warningDate)) {
        logger.info("samlCert expire in %s", timeDiff);
      } else if (isAfter(out.validity.notAfter, new Date())) {
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
};

/**
 * This method extracts the correct IDP metadata
 * from the passport strategy options.
 *
 * It's executed for every SPID login (when passport
 * middleware is configured) and when generating
 * the Service Provider metadata.
 */
export const getSamlOptions: MultiSamlConfig["getSamlOptions"] = (
  req,
  done
) => {
  try {
    // Get decoded response
    const decodedResponse = req.body?.SAMLResponse
      ? decodeBase64(req.body.SAMLResponse)
      : undefined;

    // Get SPID strategy options with IDPs metadata
    const maybeSpidStrategyOptions = O.fromNullable(
      getSpidStrategyOption(req.app)
    );
    if (O.isNone(maybeSpidStrategyOptions)) {
      throw new Error(
        "Missing Spid Strategy Option configuration inside express App"
      );
    }

    // Get the correct entry within the IDP metadata object
    const maybeEntrypointCerts = pipe(
      maybeSpidStrategyOptions,
      O.chain(spidStrategyOptions =>
        getEntrypointCerts(req, spidStrategyOptions.idp)
      )
    );
    if (O.isNone(maybeEntrypointCerts)) {
      logger.debug(
        `SPID cannot find a valid idp in spidOptions for given entityID: ${req.query.entityID}`
      );
    }
    const entrypointCerts = pipe(
      maybeEntrypointCerts,
      O.getOrElse((): IEntrypointCerts => ({ cert: [] }))
    );

    // Get authnContext (SPID level) and forceAuthn from request payload
    const maybeAuthOptions = getAuthSalmOptions(req, decodedResponse);
    if (O.isNone(maybeAuthOptions)) {
      logger.debug(
        "SPID cannot find authnContext in response %s",
        decodedResponse
      );
    }
    const authOptions = pipe(
      maybeAuthOptions,
      O.getOrElseW(() => ({}))
    );
    const options = {
      ...maybeSpidStrategyOptions.value.sp,
      ...authOptions,
      ...entrypointCerts,
      cert: Array.from(entrypointCerts.cert)
    };
    return done(null, options);
  } catch (e) {
    return done(e as Error);
  }
};

//
//  Service Provider Metadata
//

// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
const getSpidAttributesMetadata = (
  serviceProviderConfig: IServiceProviderConfig
) =>
  serviceProviderConfig.requiredAttributes
    ? serviceProviderConfig.requiredAttributes.attributes.map(item => ({
        $: {
          FriendlyName: SPID_USER_ATTRIBUTES[item] || "",
          Name: item,
          NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
        }
      }))
    : [];

// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
const getSpidOrganizationMetadata = (
  serviceProviderConfig: IServiceProviderConfig
) =>
  serviceProviderConfig.organization
    ? {
        Organization: {
          OrganizationName: {
            $: { [XML_TAGS.LANG]: "it" },
            _: serviceProviderConfig.organization.name
          },
          // must appear after organization name
          // eslint-disable-next-line sort-keys
          OrganizationDisplayName: {
            $: { [XML_TAGS.LANG]: "it" },
            _: serviceProviderConfig.organization.displayName
          },
          OrganizationURL: {
            $: { [XML_TAGS.LANG]: "it" },
            _: serviceProviderConfig.organization.URL
          }
        }
      }
    : {};

// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
const getSpidContactPersonMetadata = (
  serviceProviderConfig: IServiceProviderConfig
  // eslint-disable-next-line sonarjs/cognitive-complexity
) =>
  serviceProviderConfig.contacts
    ? serviceProviderConfig.contacts
        .map(item => {
          const contact = {
            $: {
              contactType: item.contactType
            },
            Company: item.company,
            EmailAddress: item.email,
            ...(item.phone ? { TelephoneNumber: item.phone } : {})
          };
          if (item.contactType === ContactType.OTHER) {
            return {
              Extensions: {
                ...(item.extensions.IPACode
                  ? { [SPID_TAGS.IPA_CODE]: item.extensions.IPACode }
                  : {}),
                ...(item.extensions.VATNumber
                  ? { [SPID_TAGS.VAT_NUMBER]: item.extensions.VATNumber }
                  : {}),
                ...(item.extensions?.FiscalCode
                  ? { [SPID_TAGS.FISCAL_CODE]: item.extensions.FiscalCode }
                  : {}),
                ...(item.entityType === EntityType.AGGREGATOR
                  ? { [`spid:${item.extensions.aggregatorType}`]: {} }
                  : {})
              },
              ...contact,
              $: {
                ...contact.$,
                [SPID_TAGS.ENTITY_TYPE]: item.entityType
              }
            };
          }
          return contact;
        })
        // Contacts array is limited to 3 elements
        .slice(0, 3)
    : {};

// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
const getKeyInfoForMetadata = (publicCert: string, privateKey: string) => ({
  file: privateKey,
  getKey: (): Buffer => Buffer.from(privateKey),
  getKeyInfo: (): string =>
    `<X509Data><X509Certificate>${publicCert}</X509Certificate></X509Data>`
});

export const getMetadataTamperer = (
  xmlBuilder: Builder,
  serviceProviderConfig: IServiceProviderConfig,
  samlConfig: SamlConfig
) => (generateXml: string): TE.TaskEither<Error, string> =>
  pipe(
    TE.tryCatch(() => parseStringPromise(generateXml), E.toError),
    TE.chain(o =>
      TE.tryCatch(async () => {
        // it is safe to mutate object here since it is
        // deserialized and serialized locally in this method
        const sso = o.EntityDescriptor.SPSSODescriptor[0];
        // eslint-disable-next-line functional/immutable-data
        sso.$ = {
          ...sso.$,
          AuthnRequestsSigned: true,
          WantAssertionsSigned: true
        };
        // eslint-disable-next-line functional/immutable-data
        sso.AssertionConsumerService[0].$.index = 0;
        // eslint-disable-next-line functional/immutable-data
        sso.AttributeConsumingService = {
          $: {
            index: samlConfig.attributeConsumingServiceIndex
          },
          ServiceName: {
            $: {
              [XML_TAGS.LANG]: "it"
            },
            _: serviceProviderConfig.requiredAttributes.name
          },
          // must appear after attributes
          // eslint-disable-next-line sort-keys
          RequestedAttribute: getSpidAttributesMetadata(serviceProviderConfig)
        };
        // eslint-disable-next-line functional/immutable-data
        o.EntityDescriptor = {
          ...o.EntityDescriptor,
          ...getSpidOrganizationMetadata(serviceProviderConfig)
        };
        if (serviceProviderConfig.contacts) {
          // eslint-disable-next-line functional/immutable-data
          o.EntityDescriptor = {
            ...o.EntityDescriptor,
            $: {
              ...o.EntityDescriptor.$,
              // eslint-disable-next-line @typescript-eslint/naming-convention
              "xmlns:spid": SAML_NAMESPACE.SPID
            },

            ContactPerson: getSpidContactPersonMetadata(serviceProviderConfig)
          };
        }
        return o;
      }, E.toError)
    ),
    TE.chain(_ =>
      TE.tryCatch(async () => xmlBuilder.buildObject(_), E.toError)
    ),
    TE.chain(xml =>
      TE.tryCatch(async () => {
        // sign xml metadata
        if (!samlConfig.privateCert) {
          throw new Error(
            "You must provide a private key to sign SPID service provider metadata."
          );
        }
        const sig = new xmlCrypto.SignedXml();
        const publicCert = cleanCert(serviceProviderConfig.publicCert);
        // eslint-disable-next-line functional/immutable-data
        sig.keyInfoProvider = getKeyInfoForMetadata(
          publicCert,
          samlConfig.privateCert
        );
        // eslint-disable-next-line functional/immutable-data
        sig.signatureAlgorithm =
          "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        // eslint-disable-next-line functional/immutable-data
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
          // eslint-disable-next-line sort-keys
          location: { reference: "", action: "prepend" }
        });
        return sig.getSignedXml();
      }, E.toError)
    )
  );

//
//  Authorize request
//

export const getAuthorizeRequestTamperer = (
  xmlBuilder: Builder,
  samlConfig: SamlConfig
) => (
  generateXml: string,
  lollipopParams?: ILollipopParams
): TE.TaskEither<Error, string> =>
  pipe(
    TE.tryCatch(() => parseStringPromise(generateXml), E.toError),
    TE.chain(o =>
      pipe(
        lollipopParams,
        O.fromNullable,
        E.fromOption(() => o),
        E.fold(TE.right, lParams =>
          pipe(
            lParams.hashAlgorithm,
            O.fromNullable,
            O.getOrElse(() => DEFAULT_LOLLIPOP_HASH_ALGORITHM),
            TE.of,
            TE.bindTo("hashingAlgo"),
            TE.bind("jwkThumbprint", ({ hashingAlgo }) =>
              TE.tryCatch(
                () => jose.calculateJwkThumbprint(lParams.pubKey, hashingAlgo),
                E.toError
              )
            ),
            TE.map(
              ({ hashingAlgo, jwkThumbprint }) =>
                `${hashingAlgo}-${jwkThumbprint}`
            ),
            TE.chain(requestId =>
              TE.tryCatch(async () => {
                // eslint-disable-next-line functional/immutable-data
                o["samlp:AuthnRequest"].$.ID = requestId;
                return o;
              }, E.toError)
            )
          )
        )
      )
    ),
    TE.chain(o =>
      TE.tryCatch(async () => {
        // it is safe to mutate object here since it is
        // deserialized and serialized locally in this method
        const authnRequest = o["samlp:AuthnRequest"];
        // eslint-disable-next-line fp/no-delete, functional/immutable-data
        delete authnRequest["samlp:NameIDPolicy"][0].$.AllowCreate;
        // eslint-disable-next-line functional/immutable-data
        authnRequest["saml:Issuer"][0].$.NameQualifier = samlConfig.issuer;
        // eslint-disable-next-line functional/immutable-data
        authnRequest["saml:Issuer"][0].$.Format = ISSUER_FORMAT;
        return o;
      }, E.toError)
    ),
    TE.chain(obj =>
      TE.tryCatch(async () => xmlBuilder.buildObject(obj), E.toError)
    )
  );

//
//  Validate response
//

const utcStringToDate = (value: string, tag: string): E.Either<Error, Date> =>
  pipe(
    UTCISODateFromString.decode(value),
    E.mapLeft(() => new Error(`${tag} must be an UTCISO format date string`))
  );

export const validateIssuer = (
  fatherElement: Element,
  idpIssuer: string
): E.Either<Error, Element> =>
  pipe(
    E.fromOption(() => new Error("Issuer element must be present"))(
      O.fromNullable(
        fatherElement
          .getElementsByTagNameNS(SAML_NAMESPACE.ASSERTION, "Issuer")
          .item(0)
      )
    ),
    E.chain(Issuer =>
      pipe(
        NonEmptyString.decode(Issuer.textContent?.trim()),
        E.mapLeft(() => new Error("Issuer element must be not empty")),
        E.chain(
          E.fromPredicate(
            IssuerTextContent => IssuerTextContent === idpIssuer,
            () => new Error(`Invalid Issuer. Expected value is ${idpIssuer}`)
          )
        ),
        E.map(() => Issuer)
      )
    )
  );

export const mainAttributeValidation = (validationTimestamp: number) => (
  requestOrAssertion: Element,
  acceptedClockSkewMs: number = 0
): E.Either<Error, Date> =>
  pipe(
    NonEmptyString.decode(requestOrAssertion.getAttribute("ID")),
    E.mapLeft(() => new Error("Assertion must contain a non empty ID")),
    E.map(() => requestOrAssertion.getAttribute("Version")),
    E.chain(
      E.fromPredicate(
        Version => Version === "2.0",
        () => new Error("Version version must be 2.0")
      )
    ),
    E.chain(() =>
      E.fromOption(
        () => new Error("Assertion must contain a non empty IssueInstant")
      )(O.fromNullable(requestOrAssertion.getAttribute("IssueInstant")))
    ),
    E.chain(IssueInstant => utcStringToDate(IssueInstant, "IssueInstant")),
    E.chain(
      E.fromPredicate(
        IssueInstant =>
          IssueInstant.getTime() <
          (acceptedClockSkewMs === -1
            ? Infinity
            : validationTimestamp + acceptedClockSkewMs),
        () => new Error("IssueInstant must be in the past")
      )
    )
  );

export const isEmptyNode = (element: Element): boolean => {
  if (element.childNodes.length > 1) {
    return false;
  } else if (
    element.firstChild &&
    element.firstChild.nodeType === element.ELEMENT_NODE
    // eslint-disable-next-line sonarjs/no-duplicated-branches
  ) {
    return false;
  } else if (
    element.textContent &&
    // eslint-disable-next-line no-useless-escape
    element.textContent.replace(/[\r\n\ ]+/g, "") !== ""
    // eslint-disable-next-line sonarjs/no-duplicated-branches
  ) {
    return false;
  }
  return true;
};

const isOverflowNumberOf = (
  elemArray: ReadonlyArray<Element>,
  maxNumberOfChildren: number
): boolean =>
  elemArray.filter(e => e.nodeType === e.ELEMENT_NODE).length >
  maxNumberOfChildren;

export const TransformError = t.interface({
  idpIssuer: t.string,
  message: t.string,
  numberOfTransforms: t.number
});
export type TransformError = t.TypeOf<typeof TransformError>;

export const transformsValidation = (
  targetElement: Element,
  idpIssuer: string
): E.Either<TransformError, Element> =>
  pipe(
    O.fromPredicate((elements: ReadonlyArray<Element>) => elements.length > 0)(
      Array.from(
        targetElement.getElementsByTagNameNS(
          SAML_NAMESPACE.XMLDSIG,
          "Transform"
        )
      )
    ),
    O.fold(
      () => E.right(targetElement),
      transformElements =>
        pipe(
          E.fromPredicate(
            (_: ReadonlyArray<Element>) => !isOverflowNumberOf(_, 4),
            _ =>
              TransformError.encode({
                idpIssuer,
                message: "Transform element cannot occurs more than 4 times",
                numberOfTransforms: _.length
              })
          )(transformElements),
          E.map(() => targetElement)
        )
    )
  );

const notOnOrAfterValidation = (validationTimestamp: number) => (
  element: Element,
  acceptedClockSkewMs: number = 0
): E.Either<Error, Date> =>
  pipe(
    NonEmptyString.decode(element.getAttribute("NotOnOrAfter")),
    E.mapLeft(
      () => new Error("NotOnOrAfter attribute must be a non empty string")
    ),
    E.chain(NotOnOrAfter => utcStringToDate(NotOnOrAfter, "NotOnOrAfter")),
    E.chain(
      E.fromPredicate(
        NotOnOrAfter =>
          NotOnOrAfter.getTime() >
          (acceptedClockSkewMs === -1
            ? -Infinity
            : validationTimestamp - acceptedClockSkewMs),
        () => new Error("NotOnOrAfter must be in the future")
      )
    )
  );

// eslint-disable-next-line max-lines-per-function
export const assertionValidation = (validationTimestamp: number) => (
  Assertion: Element,
  samlConfig: SamlConfig,
  InResponseTo: string,
  requestAuthnContextClassRef: string
  // eslint-disable-next-line sonarjs/cognitive-complexity
): E.Either<Error, HTMLCollectionOf<Element>> => {
  const acceptedClockSkewMs = samlConfig.acceptedClockSkewMs || 0;
  return pipe(
    E.fromOption(() => new Error("Assertion must be signed"))(
      O.fromNullable(
        Assertion.getElementsByTagNameNS(
          SAML_NAMESPACE.XMLDSIG,
          "Signature"
        ).item(0)
      )
    ),
    E.chain(notSignedWithHmacPredicate),
    // eslint-disable-next-line max-lines-per-function, sonarjs/cognitive-complexity
    E.chain(() =>
      pipe(
        E.fromOption(() => new Error("Subject element must be present"))(
          O.fromNullable(
            Assertion.getElementsByTagNameNS(
              SAML_NAMESPACE.ASSERTION,
              "Subject"
            ).item(0)
          )
        ),
        E.chain(
          E.fromPredicate(
            PR.not(isEmptyNode),
            () => new Error("Subject element must be not empty")
          )
        ),
        E.chain(Subject =>
          pipe(
            E.fromOption(() => new Error("NameID element must be present"))(
              O.fromNullable(
                Subject.getElementsByTagNameNS(
                  SAML_NAMESPACE.ASSERTION,
                  "NameID"
                ).item(0)
              )
            ),
            E.chain(
              E.fromPredicate(
                PR.not(isEmptyNode),
                () => new Error("NameID element must be not empty")
              )
            ),
            E.chain(NameID =>
              pipe(
                NonEmptyString.decode(NameID.getAttribute("Format")),
                E.mapLeft(
                  () =>
                    new Error(
                      "Format attribute of NameID element must be a non empty string"
                    )
                ),
                E.chain(
                  E.fromPredicate(
                    Format =>
                      Format ===
                      "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
                    () =>
                      new Error("Format attribute of NameID element is invalid")
                  )
                ),
                E.map(() => NameID)
              )
            ),
            E.chain(NameID =>
              pipe(
                NonEmptyString.decode(NameID.getAttribute("NameQualifier")),
                E.mapLeft(
                  () =>
                    new Error(
                      "NameQualifier attribute of NameID element must be a non empty string"
                    )
                )
              )
            ),
            E.map(() => Subject)
          )
        ),
        E.chain(Subject =>
          pipe(
            E.fromOption(
              () => new Error("SubjectConfirmation element must be present")
            )(
              O.fromNullable(
                Subject.getElementsByTagNameNS(
                  SAML_NAMESPACE.ASSERTION,
                  "SubjectConfirmation"
                ).item(0)
              )
            ),
            E.chain(
              E.fromPredicate(
                PR.not(isEmptyNode),
                () => new Error("SubjectConfirmation element must be not empty")
              )
            ),
            E.chain(SubjectConfirmation =>
              pipe(
                NonEmptyString.decode(
                  SubjectConfirmation.getAttribute("Method")
                ),
                E.mapLeft(
                  () =>
                    new Error(
                      "Method attribute of SubjectConfirmation element must be a non empty string"
                    )
                ),
                E.chain(
                  E.fromPredicate(
                    Method =>
                      Method === "urn:oasis:names:tc:SAML:2.0:cm:bearer",
                    () =>
                      new Error(
                        "Method attribute of SubjectConfirmation element is invalid"
                      )
                  )
                ),
                E.map(() => SubjectConfirmation)
              )
            ),
            E.chain(SubjectConfirmation =>
              pipe(
                E.fromOption(
                  () =>
                    new Error(
                      "SubjectConfirmationData element must be provided"
                    )
                )(
                  O.fromNullable(
                    SubjectConfirmation.getElementsByTagNameNS(
                      SAML_NAMESPACE.ASSERTION,
                      "SubjectConfirmationData"
                    ).item(0)
                  )
                ),
                E.chain(SubjectConfirmationData =>
                  pipe(
                    NonEmptyString.decode(
                      SubjectConfirmationData.getAttribute("Recipient")
                    ),
                    E.mapLeft(
                      () =>
                        new Error(
                          "Recipient attribute of SubjectConfirmationData element must be a non empty string"
                        )
                    ),
                    E.chain(
                      E.fromPredicate(
                        Recipient => Recipient === samlConfig.callbackUrl,
                        () =>
                          new Error(
                            "Recipient attribute of SubjectConfirmationData element must be equal to AssertionConsumerServiceURL"
                          )
                      )
                    ),
                    E.map(() => SubjectConfirmationData)
                  )
                ),
                E.chain(SubjectConfirmationData =>
                  pipe(
                    notOnOrAfterValidation(validationTimestamp)(
                      SubjectConfirmationData,
                      acceptedClockSkewMs
                    ),
                    E.map(() => SubjectConfirmationData)
                  )
                ),
                E.chain(SubjectConfirmationData =>
                  pipe(
                    NonEmptyString.decode(
                      SubjectConfirmationData.getAttribute("InResponseTo")
                    ),
                    E.mapLeft(
                      () =>
                        new Error(
                          "InResponseTo attribute of SubjectConfirmationData element must be a non empty string"
                        )
                    ),
                    E.chain(
                      E.fromPredicate(
                        inResponseTo => inResponseTo === InResponseTo,
                        () =>
                          new Error(
                            "InResponseTo attribute of SubjectConfirmationData element must be equal to Response InResponseTo"
                          )
                      )
                    )
                  )
                )
              )
            )
          )
        ),
        // eslint-disable-next-line max-lines-per-function
        E.chain(() =>
          pipe(
            E.fromOption(
              () => new Error("Conditions element must be provided")
            )(
              O.fromNullable(
                Assertion.getElementsByTagNameNS(
                  SAML_NAMESPACE.ASSERTION,
                  "Conditions"
                ).item(0)
              )
            ),
            E.chain(
              E.fromPredicate(
                PR.not(isEmptyNode),
                () => new Error("Conditions element must be provided")
              )
            ),
            E.chain(Conditions =>
              pipe(
                notOnOrAfterValidation(validationTimestamp)(
                  Conditions,
                  acceptedClockSkewMs
                ),
                E.map(() => Conditions)
              )
            ),
            E.chainFirst(Conditions =>
              pipe(
                NonEmptyString.decode(Conditions.getAttribute("NotBefore")),
                E.mapLeft(
                  () => new Error("NotBefore must be a non empty string")
                ),
                E.chain(NotBefore => utcStringToDate(NotBefore, "NotBefore")),
                E.chain(
                  E.fromPredicate(
                    NotBefore =>
                      NotBefore.getTime() <=
                      (acceptedClockSkewMs === -1
                        ? Infinity
                        : validationTimestamp + acceptedClockSkewMs),
                    () => new Error("NotBefore must be in the past")
                  )
                )
              )
            ),
            E.chain(Conditions =>
              pipe(
                E.fromOption(
                  () =>
                    new Error(
                      "AudienceRestriction element must be present and not empty"
                    )
                )(
                  O.fromNullable(
                    Conditions.getElementsByTagNameNS(
                      SAML_NAMESPACE.ASSERTION,
                      "AudienceRestriction"
                    ).item(0)
                  )
                ),
                E.chain(
                  E.fromPredicate(
                    PR.not(isEmptyNode),
                    // eslint-disable-next-line sonarjs/no-identical-functions
                    () =>
                      new Error(
                        "AudienceRestriction element must be present and not empty"
                      )
                  )
                ),
                E.chain(AudienceRestriction =>
                  pipe(
                    E.fromOption(() => new Error("Audience missing"))(
                      O.fromNullable(
                        AudienceRestriction.getElementsByTagNameNS(
                          SAML_NAMESPACE.ASSERTION,
                          "Audience"
                        ).item(0)
                      )
                    ),
                    E.chain(
                      E.fromPredicate(
                        Audience =>
                          Audience.textContent?.trim() === samlConfig.issuer,
                        () => new Error("Audience invalid")
                      )
                    )
                  )
                )
              )
            ),
            E.chain(() =>
              pipe(
                E.fromOption(() => new Error("Missing AuthnStatement"))(
                  O.fromNullable(
                    Assertion.getElementsByTagNameNS(
                      SAML_NAMESPACE.ASSERTION,
                      "AuthnStatement"
                    ).item(0)
                  )
                ),
                E.chain(
                  E.fromPredicate(
                    PR.not(isEmptyNode),
                    () => new Error("Empty AuthnStatement")
                  )
                ),
                E.chain(AuthnStatement =>
                  pipe(
                    E.fromOption(() => new Error("Missing AuthnContext"))(
                      O.fromNullable(
                        AuthnStatement.getElementsByTagNameNS(
                          SAML_NAMESPACE.ASSERTION,
                          "AuthnContext"
                        ).item(0)
                      )
                    ),
                    E.chain(
                      E.fromPredicate(
                        PR.not(isEmptyNode),
                        () => new Error("Empty AuthnContext")
                      )
                    ),
                    E.chain(AuthnContext =>
                      pipe(
                        E.fromOption(
                          () => new Error("Missing AuthnContextClassRef")
                        )(
                          O.fromNullable(
                            AuthnContext.getElementsByTagNameNS(
                              SAML_NAMESPACE.ASSERTION,
                              "AuthnContextClassRef"
                            ).item(0)
                          )
                        ),
                        E.chain(
                          E.fromPredicate(
                            PR.not(isEmptyNode),
                            () => new Error("Empty AuthnContextClassRef")
                          )
                        ),
                        E.map(AuthnContextClassRef =>
                          AuthnContextClassRef.textContent?.trim()
                        ),
                        E.chain(
                          E.fromPredicate(
                            AuthnContextClassRef =>
                              AuthnContextClassRef === SPID_LEVELS.SpidL1 ||
                              AuthnContextClassRef === SPID_LEVELS.SpidL2 ||
                              AuthnContextClassRef === SPID_LEVELS.SpidL3,
                            () =>
                              new Error("Invalid AuthnContextClassRef value")
                          )
                        ),
                        E.chain(
                          E.fromPredicate(
                            AuthnContextClassRef =>
                              requestAuthnContextClassRef === SPID_LEVELS.SpidL2
                                ? AuthnContextClassRef === SPID_LEVELS.SpidL2 ||
                                  AuthnContextClassRef === SPID_LEVELS.SpidL3
                                : requestAuthnContextClassRef ===
                                  SPID_LEVELS.SpidL1
                                ? AuthnContextClassRef === SPID_LEVELS.SpidL1 ||
                                  AuthnContextClassRef === SPID_LEVELS.SpidL2 ||
                                  AuthnContextClassRef === SPID_LEVELS.SpidL3
                                : requestAuthnContextClassRef ===
                                  AuthnContextClassRef,
                            () =>
                              new Error(
                                "AuthnContextClassRef value not expected"
                              )
                          )
                        )
                      )
                    )
                  )
                )
              )
            ),
            E.chain(() =>
              pipe(
                E.fromOption(
                  () => new Error("AttributeStatement must contains Attributes")
                )(
                  pipe(
                    O.fromNullable(
                      Assertion.getElementsByTagNameNS(
                        SAML_NAMESPACE.ASSERTION,
                        "AttributeStatement"
                      ).item(0)
                    ),
                    O.map(AttributeStatement =>
                      AttributeStatement.getElementsByTagNameNS(
                        SAML_NAMESPACE.ASSERTION,
                        "Attribute"
                      )
                    )
                  )
                ),
                E.chain(
                  E.fromPredicate(
                    Attributes =>
                      Attributes.length > 0 &&
                      !Array.from(Attributes).some(isEmptyNode),
                    () =>
                      new Error(
                        "Attribute element must be present and not empty"
                      )
                  )
                )
              )
            )
          )
        )
      )
    )
  );
};
