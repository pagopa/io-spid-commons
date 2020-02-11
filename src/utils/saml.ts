/**
 * Methods used to tamper passport-saml generated SAML XML.
 *
 * SPID protocol has some peculiarities that need to be addressed
 * to make request, metadata and responses compliant.
 */
import { distanceInWordsToNow, isAfter, subDays } from "date-fns";
import { Request as ExpressRequest } from "express";
import { flatten } from "fp-ts/lib/Array";
import {
  Either,
  fromOption,
  fromPredicate,
  isLeft,
  left,
  right,
  toError
} from "fp-ts/lib/Either";
import {
  fromEither,
  fromNullable,
  isNone,
  none,
  Option,
  some,
  tryCatch as optionTryCatch
} from "fp-ts/lib/Option";
import { collect, lookup } from "fp-ts/lib/Record";
import { TaskEither, tryCatch } from "fp-ts/lib/TaskEither";
import * as t from "io-ts";
import { UTCISODateFromString } from "italia-ts-commons/lib/dates";
import { NonEmptyString } from "italia-ts-commons/lib/strings";
import { pki } from "node-forge";
import { SamlConfig } from "passport-saml";
// tslint:disable-next-line: no-submodule-imports
import { MultiSamlConfig } from "passport-saml/multiSamlStrategy";
import * as xmlCrypto from "xml-crypto";
import { Builder, parseStringPromise } from "xml2js";
import { DOMParser } from "xmldom";
import { SPID_LEVELS, SPID_URLS, SPID_USER_ATTRIBUTES } from "../config";
import { PreValidateResponseT } from "../strategy/spid";
import { logger } from "./logger";
import {
  getSpidStrategyOption,
  IServiceProviderConfig,
  ISpidStrategyOptions
} from "./middleware";

export type SamlAttributeT = keyof typeof SPID_USER_ATTRIBUTES;

interface IEntrypointCerts {
  // tslint:disable-next-line: readonly-array
  cert: NonEmptyString[];
  entryPoint?: string;
}

export const SAML_NAMESPACE = {
  ASSERTION: "urn:oasis:names:tc:SAML:2.0:assertion",
  PROTOCOL: "urn:oasis:names:tc:SAML:2.0:protocol"
};

const decodeBase64 = (s: string) => Buffer.from(s, "base64").toString("utf8");

/**
 * Remove prefix and suffix from x509 certificate.
 */
const cleanCert = (cert: string) =>
  cert
    .replace(/-+BEGIN CERTIFICATE-+\r?\n?/, "")
    .replace(/-+END CERTIFICATE-+\r?\n?/, "")
    .replace(/\r\n/g, "\n");

const SAMLResponse = t.type({
  SAMLResponse: t.string
});

export const getXmlFromSamlResponse = (body: unknown): Option<Document> =>
  fromEither(SAMLResponse.decode(body))
    .map(_ => decodeBase64(_.SAMLResponse))
    .chain(_ => optionTryCatch(() => new DOMParser().parseFromString(_)));

/**
 * Extract StatusMessage from SAML response
 *
 * ie. for <StatusMessage>ErrorCode nr22</StatusMessage>
 * returns "22"
 */
export function getErrorCodeFromResponse(doc: Document): Option<string> {
  return fromNullable(
    doc.getElementsByTagNameNS(SAML_NAMESPACE.PROTOCOL, "StatusMessage")
  )
    .chain(responseStatusMessageEl => {
      return responseStatusMessageEl &&
        responseStatusMessageEl[0] &&
        responseStatusMessageEl[0].textContent
        ? some(responseStatusMessageEl[0].textContent.trim())
        : none;
    })
    .chain(errorString => {
      const indexString = "ErrorCode nr";
      const errorCode = errorString.slice(
        errorString.indexOf(indexString) + indexString.length
      );
      return errorCode !== "" ? some(errorCode) : none;
    });
}

/**
 * Extracts the issuer field from the response body.
 */
export const getSamlIssuer = (doc: Document): Option<string> => {
  return fromNullable(
    doc.getElementsByTagNameNS(SAML_NAMESPACE.ASSERTION, "Issuer").item(0)
  ).mapNullable(_ => _.textContent);
};

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
      // collect all IDP certificates in case no entityID is provided
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
    SAML_NAMESPACE.ASSERTION,
    "AuthnContextClassRef"
  );
  return responseAuthLevelEl[0] && responseAuthLevelEl[0].textContent
    ? some(responseAuthLevelEl[0].textContent.trim())
    : none;
};

/**
 * Extracts the correct SPID level from response.
 */
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

/**
 * Log SPID response body, entityID / authLevel.
 */
const logSpidResponse = (req: ExpressRequest, decodedResponse?: string) => {
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
 * Reads dates information in x509 certificate
 * and logs remaining time to its expiration date.
 *
 * @param samlCert x509 certificate as string
 */
export function logSamlCertExpiration(samlCert: string): void {
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
}

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
    const decodedResponse =
      req.body && req.body.SAMLResponse
        ? decodeBase64(req.body.SAMLResponse)
        : undefined;

    logSpidResponse(req, decodedResponse);

    // Get SPID strategy options with IDPs metadata
    const spidStrategyOptions = getSpidStrategyOption(req.app);

    // Get the correct entry within the IDP metadata object
    const maybeEntrypointCerts = getEntrypointCerts(
      req,
      spidStrategyOptions.idp
    );
    if (isNone(maybeEntrypointCerts)) {
      logger.debug(
        `SPID cannot find a valid idp in spidOptions for given entityID: ${req.query.entityID}`
      );
    }
    const entrypointCerts = maybeEntrypointCerts.getOrElse(
      {} as IEntrypointCerts
    );

    // Get authnContext (SPID level) and forceAuthn from request payload
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
  } catch (e) {
    return done(e);
  }
};

//
//  Service Provider Metadata
//

const getSpidAttributesMetadata = (
  serviceProviderConfig: IServiceProviderConfig
) => {
  return serviceProviderConfig.requiredAttributes
    ? serviceProviderConfig.requiredAttributes.attributes.map(item => ({
        $: {
          FriendlyName: SPID_USER_ATTRIBUTES[item] || "",
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

export const getMetadataTamperer = (
  xmlBuilder: Builder,
  serviceProviderConfig: IServiceProviderConfig,
  samlConfig: SamlConfig
) => (generateXml: string): TaskEither<Error, string> => {
  return tryCatch(() => parseStringPromise(generateXml), toError)
    .chain(o =>
      tryCatch(async () => {
        // it is safe to mutate object here since it is
        // deserialized and serialized locally in this method
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
          RequestedAttribute: getSpidAttributesMetadata(serviceProviderConfig)
        };
        // tslint:disable-next-line: no-object-mutation
        o.EntityDescriptor = {
          ...o.EntityDescriptor,
          ...getSpidOrganizationMetadata(serviceProviderConfig)
        };
        return o;
      }, toError)
    )
    .chain(_ => tryCatch(async () => xmlBuilder.buildObject(_), toError))
    .chain(xml =>
      tryCatch(async () => {
        // sign xml metadata
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
    );
};

//
//  Authorize request
//

export const getAuthorizeRequestTamperer = (
  xmlBuilder: Builder,
  _: IServiceProviderConfig,
  samlConfig: SamlConfig
) => (generateXml: string): TaskEither<Error, string> => {
  return tryCatch(() => parseStringPromise(generateXml), toError)
    .chain(o =>
      tryCatch(async () => {
        // it is safe to mutate object here since it is
        // deserialized and serialized locally in this method
        // tslint:disable-next-line: no-any
        const authnRequest = o["samlp:AuthnRequest"];
        // tslint:disable-next-line: no-object-mutation no-delete
        delete authnRequest["samlp:NameIDPolicy"][0].$.AllowCreate;
        // tslint:disable-next-line: no-object-mutation
        authnRequest["saml:Issuer"][0].$.NameQualifier = samlConfig.issuer;
        // tslint:disable-next-line: no-object-mutation
        authnRequest["saml:Issuer"][0].$.Format =
          "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
        return o;
      }, toError)
    )
    .chain(obj => tryCatch(async () => xmlBuilder.buildObject(obj), toError));
};

//
//  Validate response
//

const utcStringToDate = (value: string, tag: string): Either<Error, Date> => {
  const maybeDate =
    value.length === 24
      ? UTCISODateFromString.decode(value)
      : UTCISODateFromString.decode(value.replace("Z", ".000Z"));
  return isLeft(maybeDate)
    ? left(new Error(`${tag} must be an UTCISO format date string`))
    : right(maybeDate.value);
};

const validateIssuer = (fatherElement: Element): Either<Error, void> => {
  const IssuerElement = fatherElement
    .getElementsByTagNameNS(SAML_NAMESPACE.ASSERTION, "Issuer")
    .item(0);
  if (
    !IssuerElement ||
    !IssuerElement.textContent ||
    IssuerElement.textContent === ""
  ) {
    return left(new Error("Issuer element must be present and not empty"));
  }
  // TODO: Must validate that Issuer value is equal to EntityID IDP (29)(69)
  /*if (IssuerElement.textContent !== samlConfig.idpIssuer) {
    throw new Error(`"Invalid Issuer value: "${samlConfig.idpIssuer}`);
  }*/
  const IssuerFormatValue = IssuerElement.getAttribute("Format");
  if (!IssuerFormatValue) {
    return left(
      new Error("Format attribute of Issuer element must be present")
    );
  }
  if (
    IssuerFormatValue !== "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
  ) {
    return left(new Error("Format attribute of Issuer element is invalid"));
  }
  return right(undefined);
};

const mainAttributeValidation = (
  requestOrAssertion: Element
): Either<Error, Date> => {
  return NonEmptyString.decode(requestOrAssertion.getAttribute("ID"))
    .mapLeft(() => new Error("Assertion must contain a non empty ID"))
    .map(() => requestOrAssertion.getAttribute("Version"))
    .chain(
      fromPredicate(
        Version => Version !== "2.0",
        () => new Error("Version version must be 2.0")
      )
    )
    .chain(() =>
      fromOption(new Error("Assertion must contain a non empty IssueInstant"))(
        fromNullable(requestOrAssertion.getAttribute("IssueInstant"))
      )
    )
    .chain(IssueInstant => utcStringToDate(IssueInstant, "IssueInstant"))
    .chain(
      fromPredicate(
        _ => _.getTime() > Date.now(),
        () => new Error("IssueInstant must be in the past")
      )
    );
};

const isEmptyNode = (element: Element): boolean => {
  if (element.childNodes.length > 1) {
    return false;
  } else if (
    element.firstChild &&
    element.firstChild.nodeType === element.ELEMENT_NODE
  ) {
    return false;
  } else if (
    element.textContent &&
    element.textContent.replace(/[\r\n\ ]+/g, "") !== ""
  ) {
    return false;
  }
  return true;
};

const notOnOrAfterValidation = (element: Element) => {
  return NonEmptyString.decode(element.getAttribute("NotOnOrAfter"))
    .mapLeft(
      () => new Error("NotOnOrAfter attribute must be a non empty string")
    )
    .chain(NotOnOrAfter => utcStringToDate(NotOnOrAfter, "NotOnOrAfter"))
    .chain(
      fromPredicate(
        NotOnOrAfter => NotOnOrAfter.getTime() < Date.now(),
        () => new Error("NotOnOrAfter must be in the future")
      )
    );
};

const assertionValidation = (
  Assertion: Element,
  samlConfig: SamlConfig,
  InResponseTo: string
  // tslint:disable-next-line: no-big-function
): Either<Error, void> => {
  return fromOption(new Error("Subject element must be present"))(
    fromNullable(
      Assertion.getElementsByTagNameNS(
        SAML_NAMESPACE.ASSERTION,
        "Subject"
      ).item(0)
    )
  )
    .chain(
      fromPredicate(
        isEmptyNode,
        () => new Error("Subject element must be not empty")
      )
    )
    .chain(Subject =>
      fromOption(new Error("NameID element must be present"))(
        fromNullable(
          Subject.getElementsByTagNameNS(
            SAML_NAMESPACE.ASSERTION,
            "NameID"
          ).item(0)
        )
      )
        .chain(
          fromPredicate(
            isEmptyNode,
            () => new Error("NameID element must be not empty")
          )
        )
        .chain(NameID =>
          NonEmptyString.decode(NameID.getAttribute("Format"))
            .mapLeft(
              () =>
                new Error(
                  "Format attribute of NameID element must be a non empty string"
                )
            )
            .chain(
              fromPredicate(
                Format =>
                  Format !==
                  "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
                () => new Error("Format attribute of NameID element is invalid")
              )
            )
            .map(() => NameID)
        )
        .chain(NameID =>
          NonEmptyString.decode(NameID.getAttribute("NameQualifier")).mapLeft(
            () =>
              new Error(
                "NameQualifier attribute of NameID element must be a non empty string"
              )
          )
        )
        .map(() => Subject)
    )
    .chain(Subject =>
      fromOption(new Error("SubjectConfirmation element must be present"))(
        fromNullable(
          Subject.getElementsByTagNameNS(
            SAML_NAMESPACE.ASSERTION,
            "SubjectConfirmation"
          ).item(0)
        )
      )
        .chain(
          fromPredicate(
            isEmptyNode,
            () => new Error("SubjectConfirmation element must be not empty")
          )
        )
        .chain(SubjectConfirmation =>
          NonEmptyString.decode(SubjectConfirmation.getAttribute("Method"))
            .mapLeft(
              () =>
                new Error(
                  "Method attribute of SubjectConfirmation element must be a non empty string"
                )
            )
            .chain(
              fromPredicate(
                Method => Method !== "urn:oasis:names:tc:SAML:2.0:cm:bearer",
                () =>
                  new Error(
                    "Method attribute of SubjectConfirmation element is invalid"
                  )
              )
            )
            .map(() => SubjectConfirmation)
        )
        .chain(SubjectConfirmation =>
          fromOption(
            new Error("SubjectConfirmationData element must be provided")
          )(
            fromNullable(
              SubjectConfirmation.getElementsByTagNameNS(
                SAML_NAMESPACE.ASSERTION,
                "SubjectConfirmationData"
              ).item(0)
            )
          )
            .chain(SubjectConfirmationData =>
              NonEmptyString.decode(
                SubjectConfirmationData.getAttribute("Recipient")
              )
                .mapLeft(
                  () =>
                    new Error(
                      "Recipient attribute of SubjectConfirmationData element must be a non empty string"
                    )
                )
                .chain(
                  fromPredicate(
                    Recipient => Recipient !== samlConfig.callbackUrl,
                    () =>
                      new Error(
                        "Recipient attribute of SubjectConfirmationData element must be equal to AssertionConsumerServiceURL"
                      )
                  )
                )
                .map(() => SubjectConfirmationData)
            )
            .chain(SubjectConfirmationData =>
              notOnOrAfterValidation(SubjectConfirmationData).map(
                () => SubjectConfirmationData
              )
            )
            .chain(SubjectConfirmationData =>
              NonEmptyString.decode(
                SubjectConfirmationData.getAttribute("InResponseTo")
              )
                .mapLeft(
                  () =>
                    new Error(
                      "InResponseTo attribute of SubjectConfirmationData element must be a non empty string"
                    )
                )
                .chain(
                  fromPredicate(
                    inResponseTo => inResponseTo !== InResponseTo,
                    () =>
                      new Error(
                        "InResponseTo attribute of SubjectConfirmationData element must be equal to Response InResponseTo"
                      )
                  )
                )
            )
        )
    )
    .chain(() => validateIssuer(Assertion))
    .chain(() =>
      fromOption(new Error("Conditions element must be provided"))(
        fromNullable(
          Assertion.getElementsByTagNameNS(
            SAML_NAMESPACE.ASSERTION,
            "Conditions"
          ).item(0)
        )
      )
        .chain(
          fromPredicate(
            isEmptyNode,
            () => new Error("Conditions element must be provided")
          )
        )
        .chain(Conditions =>
          notOnOrAfterValidation(Conditions).map(() => Conditions)
        )
        .chain(Conditions =>
          NonEmptyString.decode(Conditions.getAttribute("NotBefore"))
            .mapLeft(() => new Error("NotBefore must be a non empty string"))
            .chain(NotBefore => utcStringToDate(NotBefore, "NotBefore"))
            .chain(
              fromPredicate(
                NotBefore => NotBefore.getTime() > Date.now(),
                () => new Error("NotBefore must be in the past")
              )
            )
            .map(() => Conditions)
        )
        .chain(Conditions =>
          fromOption(
            new Error(
              "AudienceRestriction element must be present and not empty"
            )
          )(
            fromNullable(
              Conditions.getElementsByTagNameNS(
                SAML_NAMESPACE.ASSERTION,
                "AudienceRestriction"
              ).item(0)
            )
          )
            .chain(
              fromPredicate(
                isEmptyNode,
                () =>
                  new Error(
                    "AudienceRestriction element must be present and not empty"
                  )
              )
            )
            .chain(AudienceRestriction =>
              fromOption(new Error("Audience missing"))(
                fromNullable(
                  AudienceRestriction.getElementsByTagNameNS(
                    SAML_NAMESPACE.ASSERTION,
                    "Audience"
                  ).item(0)
                )
              ).chain(
                fromPredicate(
                  Audience => Audience.textContent !== samlConfig.issuer,
                  () => new Error("Audience invalid")
                )
              )
            )
        )
        .chain(() =>
          fromOption(new Error("Missing AuthnStatement"))(
            fromNullable(
              Assertion.getElementsByTagNameNS(
                SAML_NAMESPACE.ASSERTION,
                "AuthnStatement"
              ).item(0)
            )
          )
            .chain(
              fromPredicate(
                isEmptyNode,
                () => new Error("Empty AuthnStatement")
              )
            )
            .chain(AuthnStatement =>
              fromOption(new Error("Missing AuthnContext"))(
                fromNullable(
                  AuthnStatement.getElementsByTagNameNS(
                    SAML_NAMESPACE.ASSERTION,
                    "AuthnContext"
                  ).item(0)
                )
              )
                .chain(
                  fromPredicate(
                    isEmptyNode,
                    () => new Error("Empty AuthnContext")
                  )
                )
                .chain(
                  AuthnContext =>
                    fromOption(new Error("Missing AuthnContextClassRef"))(
                      fromNullable(
                        AuthnContext.getElementsByTagNameNS(
                          SAML_NAMESPACE.ASSERTION,
                          "AuthnContextClassRef"
                        ).item(0)
                      )
                    )
                      .chain(
                        fromPredicate(
                          isEmptyNode,
                          () => new Error("Empty AuthnContextClassRef")
                        )
                      )
                      .chain(
                        fromPredicate(
                          AuthnContextClassRef =>
                            AuthnContextClassRef.textContent !==
                              SPID_LEVELS.SpidL1 &&
                            AuthnContextClassRef.textContent !==
                              SPID_LEVELS.SpidL2 &&
                            AuthnContextClassRef.textContent !==
                              SPID_LEVELS.SpidL3,
                          () => new Error("Invalid AuthnContextClassRef value")
                        )
                      ) // TODO: Check AuthnContextClassRef with request protocol value (94)(95)(96)
                )
            )
        )
        .chain(() =>
          fromNullable(
            Assertion.getElementsByTagNameNS(
              SAML_NAMESPACE.ASSERTION,
              "AttributeStatement"
            ).item(0)
          )
            .map(AttributeStatement =>
              AttributeStatement.getElementsByTagNameNS(
                SAML_NAMESPACE.ASSERTION,
                "Attribute"
              )
            )
            .map(
              // TODO: Attribute into the response different from the Attribute into the request (103)
              fromPredicate(
                Attributes =>
                  Attributes.length === 0 ||
                  Array.from(Attributes).some(isEmptyNode),
                () =>
                  new Error("Attribute element must be present and not empty")
              )
            )
            .fold(right(undefined), _ =>
              isLeft(_) ? left(_.value) : right(undefined)
            )
        )
    );
};

export const preValidateResponse: PreValidateResponseT = (
  samlConfig,
  body,
  callback
) => {
  try {
    const maybeDoc = getXmlFromSamlResponse(body);
    if (isNone(maybeDoc)) {
      throw new Error("Empty SAML response");
    }
    const doc = maybeDoc.value;

    const ErrorOrResponseAndAssertion = fromOption(
      new Error("Missing Reponse element inside SAML Response")
    )(
      fromNullable(
        doc.getElementsByTagNameNS(SAML_NAMESPACE.PROTOCOL, "Response").item(0)
      )
    )
      .chain(Response =>
        mainAttributeValidation(Response).map(IssueInstant => ({
          IssueInstant,
          Response
        }))
      )
      .chain(_ =>
        NonEmptyString.decode(_.Response.getAttribute("Destination"))
          .mapLeft(
            () => new Error("Response must contain a non empty Destination")
          )
          .chain(
            fromPredicate(
              Destination => Destination !== samlConfig.callbackUrl,
              () =>
                new Error(
                  "Destination must be equal to AssertionConsumerServiceURL"
                )
            )
          )
          .map(() => _)
      )
      .chain(_ => validateIssuer(_.Response).map(() => _))
      .chain(_ =>
        fromOption(new Error("Status element must be present"))(
          fromNullable(
            _.Response.getElementsByTagNameNS(
              SAML_NAMESPACE.PROTOCOL,
              "Status"
            ).item(0)
          )
        )
          .mapLeft(
            () => new Error("Status element must be present into Response")
          )
          .chain(
            fromPredicate(
              isEmptyNode,
              () => new Error("Status element must be present not empty")
            )
          )
          .chain(Status =>
            fromOption(new Error("StatusCode element must be present"))(
              fromNullable(
                Status.getElementsByTagNameNS(
                  SAML_NAMESPACE.PROTOCOL,
                  "StatusCode"
                ).item(0)
              )
            )
          )
          .chain(StatusCode =>
            fromOption(new Error("StatusCode must contain a non empty Value"))(
              fromNullable(StatusCode.getAttribute("Value"))
            )
              .chain(
                fromPredicate(
                  Value =>
                    Value !== "urn:oasis:names:tc:SAML:2.0:status:Success",
                  () => new Error("Value attribute of StatusCode is invalid")
                ) // TODO: Must be shown an error page to the user (26)
              )
              .map(() => _)
          )
      )
      .chain(_ =>
        fromOption(new Error("Assertion element must be present"))(
          fromNullable(
            _.Response.getElementsByTagNameNS(
              SAML_NAMESPACE.ASSERTION,
              "Assertion"
            ).item(0)
          )
        ).map(Assertion => ({
          Assertion,
          ..._
        }))
      )
      .chain(_ =>
        NonEmptyString.decode(_.Response.getAttribute("InResponseTo"))
          .mapLeft(
            () => new Error("InResponseTo must contain a non empty string")
          )
          .chain(InResponseTo =>
            assertionValidation(_.Assertion, samlConfig, InResponseTo).map(
              () => InResponseTo
            )
          )
          .map(InResponseTo => ({ ..._, InResponseTo }))
      )
      .chain(_ =>
        mainAttributeValidation(_.Assertion).map(IssueInstant => ({
          AssertionIssueInstant: IssueInstant,
          ..._
        }))
      )
      .mapLeft(callback);
    if (isLeft(ErrorOrResponseAndAssertion)) {
      return;
    }
    samlConfig.cacheProvider?.get(
      ErrorOrResponseAndAssertion.value.InResponseTo,
      (err, value) => {
        try {
          if (err) {
            throw new Error("Error reading the cache provider");
          }
          const RequestIssueInstant = new Date(value);
          if (
            ErrorOrResponseAndAssertion.value.IssueInstant.getTime() <
            RequestIssueInstant.getTime()
          ) {
            throw new Error(
              "Request IssueInstant must after Request IssueInstant"
            );
          }
          if (
            ErrorOrResponseAndAssertion.value.AssertionIssueInstant.getTime() <
            RequestIssueInstant.getTime()
          ) {
            throw new Error(
              "Assertion IssueInstant must after Request IssueInstant"
            );
          }
          callback(null, true);
        } catch (e) {
          callback(e);
        }
      }
    );
  } catch (e) {
    logger.error("Error parsing IDP response:%s", e.message);
    callback(e);
  }
};
