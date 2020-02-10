/**
 * Methods used to tamper passport-saml generated SAML XML.
 *
 * SPID protocol has some peculiarities that need to be addressed
 * to make request, metadata and responses compliant.
 */
import { distanceInWordsToNow, isAfter, subDays } from "date-fns";
import { Request as ExpressRequest } from "express";
import { flatten } from "fp-ts/lib/Array";
import { isLeft, toError } from "fp-ts/lib/Either";
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

const utcStringToDate = (value: string, tag: string): Date => {
  const maybeDate =
    value.length === 24
      ? UTCISODateFromString.decode(value)
      : UTCISODateFromString.decode(value.replace("Z", ".000Z"));
  if (isLeft(maybeDate)) {
    throw new Error(`${tag} must be an UTCISO format date string`);
  }
  return maybeDate.value;
};

const validateIssuer = (fatherElement: Element) => {
  const IssuerElement = fatherElement
    .getElementsByTagNameNS(SAML_NAMESPACE.ASSERTION, "Issuer")
    .item(0);
  if (
    !IssuerElement ||
    !IssuerElement.textContent ||
    IssuerElement.textContent === ""
  ) {
    throw new Error("Issuer element must be present and not empty");
  }
  // TODO: Must validate that Issuer value is equal to EntityID IDP (29)(69)
  /*if (IssuerElement.textContent !== samlConfig.idpIssuer) {
    throw new Error(`"Invalid Issuer value: "${samlConfig.idpIssuer}`);
  }*/
  const IssuerFormatValue = IssuerElement.getAttribute("Format");
  if (!IssuerFormatValue) {
    throw new Error("Format attribute of Issuer element must be present");
  }
  if (
    IssuerFormatValue !== "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
  ) {
    throw new Error("Format attribute of Issuer element is invalid");
  }
};

const mainAttributeValidation = (requestOrAssertion: Element) => {
  const ID = requestOrAssertion.getAttribute("ID");
  if (!ID && ID === "") {
    throw new Error("Assertion must contain a non empty ID");
  }
  const Version = requestOrAssertion.getAttribute("Version");
  if (Version !== "2.0") {
    throw new Error("Version version must be 2.0");
  }
  const IssueInstant = requestOrAssertion.getAttribute("IssueInstant");
  if (!IssueInstant) {
    throw new Error("Assertion must contain a non empty IssueInstant");
  }
  const IssueInstantDate = utcStringToDate(IssueInstant, "IssueInstant");
  if (IssueInstantDate.getTime() > Date.now()) {
    throw new Error("IssueInstant must be in the past");
  }
  return IssueInstantDate;
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
    element.textContent
      ?.split("\r") // Exclude return character
      .join("")
      .split("\n") // Exclude new line character
      .join("")
      .split(" ") // Exclude spaces
      .join("") !== ""
  ) {
    return false;
  }
  return true;
};

const notOnOrAfterValidation = (element: Element) => {
  const notOnOrAfter = element.getAttribute("NotOnOrAfter");
  if (!notOnOrAfter || notOnOrAfter === "") {
    throw new Error("NotOnOrAfter attribute must be a non empty string");
  }
  const notOnOrAfterDate = utcStringToDate(notOnOrAfter, "NotOnOrAfter");
  if (notOnOrAfterDate.getTime() < Date.now()) {
    throw new Error("NotOnOrAfter must be in the future");
  }
};

const assertionValidation = (
  Assertion: Element,
  samlConfig: SamlConfig,
  InResponseTo: string
) => {
  const Subject = Assertion.getElementsByTagNameNS(
    SAML_NAMESPACE.ASSERTION,
    "Subject"
  ).item(0);
  if (!Subject || isEmptyNode(Subject)) {
    throw new Error("A non empty Subject element must be present");
  }
  const SubjectNameID = Subject.getElementsByTagNameNS(
    SAML_NAMESPACE.ASSERTION,
    "NameID"
  ).item(0);
  if (!SubjectNameID || isEmptyNode(SubjectNameID)) {
    throw new Error("A non empty NameID element must be present");
  }
  const FormatNameID = SubjectNameID.getAttribute("Format");
  if (!FormatNameID || FormatNameID === "") {
    throw new Error(
      "Format attribute of NameID element must be a non empty string"
    );
  }
  if (FormatNameID !== "urn:oasis:names:tc:SAML:2.0:nameid-format:transient") {
    throw new Error("Format attribute of NameID element is invalid");
  }
  const NameQualifierNameID = SubjectNameID.getAttribute("NameQualifier");
  if (!NameQualifierNameID || NameQualifierNameID === "") {
    throw new Error(
      "NameQualifier attribute of NameID element must be a non empty string"
    );
  }
  const SubjectConfirmation = Subject.getElementsByTagNameNS(
    SAML_NAMESPACE.ASSERTION,
    "SubjectConfirmation"
  ).item(0);
  if (!SubjectConfirmation || isEmptyNode(SubjectConfirmation)) {
    throw new Error("SubjectConfirmation element must be present");
  }
  const MethodSubjectConfirmation = SubjectConfirmation.getAttribute("Method");
  if (!MethodSubjectConfirmation || MethodSubjectConfirmation === "") {
    throw new Error(
      "Method attribute of SubjectConfirmation element must be a non empty string"
    );
  }
  if (MethodSubjectConfirmation !== "urn:oasis:names:tc:SAML:2.0:cm:bearer") {
    throw new Error(
      "Method attribute of SubjectConfirmation element is invalid"
    );
  }
  const SubjectConfirmationData = SubjectConfirmation.getElementsByTagNameNS(
    SAML_NAMESPACE.ASSERTION,
    "SubjectConfirmationData"
  ).item(0);
  if (!SubjectConfirmationData) {
    throw new Error("SubjectConfirmationData element must be provided");
  }
  const RecipientSubjectConfirmationData = SubjectConfirmationData.getAttribute(
    "Recipient"
  );
  if (
    !RecipientSubjectConfirmationData ||
    RecipientSubjectConfirmationData === ""
  ) {
    throw new Error(
      "Recipient attribute of SubjectConfirmationData element must be a non empty string"
    );
  }
  if (RecipientSubjectConfirmationData !== samlConfig.callbackUrl) {
    throw new Error(
      "Recipient attribute of SubjectConfirmationData element must be equal to AssertionConsumerServiceURL"
    );
  }
  const InReponseToSubjectConfirmationData = SubjectConfirmationData.getAttribute(
    "InResponseTo"
  );
  if (
    !InReponseToSubjectConfirmationData ||
    InReponseToSubjectConfirmationData === ""
  ) {
    throw new Error(
      "InResponseTo attribute of SubjectConfirmationData element must be a non empty string"
    );
  }
  if (InReponseToSubjectConfirmationData !== InResponseTo) {
    throw new Error(
      "InResponseTo attribute of SubjectConfirmationData element must be equal to Response InResponseTo"
    );
  }
  notOnOrAfterValidation(SubjectConfirmationData);
  validateIssuer(Assertion);
  const Conditions = Assertion.getElementsByTagNameNS(
    SAML_NAMESPACE.ASSERTION,
    "Conditions"
  ).item(0);
  if (!Conditions || isEmptyNode(Conditions)) {
    throw new Error("Conditions element must be provided");
  }
  const NotBeforeConditions = Conditions.getAttribute("NotBefore");
  if (!NotBeforeConditions || NotBeforeConditions === "") {
    throw new Error("NotBefore must be a non empty string");
  }
  const NotBeforeConditionsValue = utcStringToDate(
    NotBeforeConditions,
    "NotBefore"
  );
  if (NotBeforeConditionsValue.getTime() > Date.now()) {
    throw new Error("NotBefore must be in the past");
  }
  notOnOrAfterValidation(Conditions);
  const AudienceRestriction = Conditions.getElementsByTagNameNS(
    SAML_NAMESPACE.ASSERTION,
    "AudienceRestriction"
  ).item(0);
  if (!AudienceRestriction || isEmptyNode(AudienceRestriction)) {
    throw new Error(
      "AudienceRestriction element must be present and not empty"
    );
  }
  const Audience = AudienceRestriction.getElementsByTagNameNS(
    SAML_NAMESPACE.ASSERTION,
    "Audience"
  ).item(0);
  if (!Audience || Audience.textContent !== samlConfig.issuer) {
    throw new Error("Audience missing or invalid");
  }
  const AuthnStatement = Assertion.getElementsByTagNameNS(
    SAML_NAMESPACE.ASSERTION,
    "AuthnStatement"
  ).item(0);
  if (!AuthnStatement || isEmptyNode(AuthnStatement)) {
    throw new Error("Missing or empty AuthnStatement");
  }
  const AuthnContext = AuthnStatement.getElementsByTagNameNS(
    SAML_NAMESPACE.ASSERTION,
    "AuthnContext"
  ).item(0);

  if (!AuthnContext || isEmptyNode(AuthnContext)) {
    throw new Error("Missing or empty AuthnContext");
  }

  const AuthnContextClassRef = AuthnContext.getElementsByTagNameNS(
    SAML_NAMESPACE.ASSERTION,
    "AuthnContextClassRef"
  ).item(0);
  if (!AuthnContextClassRef || isEmptyNode(AuthnContextClassRef)) {
    throw new Error("AuthnContextClassRef must be a non empty string");
  }
  // TODO: Check AuthnContextClassRef with reqest protocol value (94)(95)(96)
  if (
    AuthnContextClassRef.textContent !== SPID_LEVELS.SpidL1 &&
    AuthnContextClassRef.textContent !== SPID_LEVELS.SpidL2 &&
    AuthnContextClassRef.textContent !== SPID_LEVELS.SpidL3
  ) {
    throw new Error("Invalid AuthnContextClassRef value");
  }
  const AttributeStatement = Assertion.getElementsByTagNameNS(
    SAML_NAMESPACE.ASSERTION,
    "AttributeStatement"
  ).item(0);
  if (AttributeStatement) {
    const Attributes = AttributeStatement.getElementsByTagNameNS(
      SAML_NAMESPACE.ASSERTION,
      "Attribute"
    );
    if (Attributes.length === 0 || Array.from(Attributes).some(isEmptyNode)) {
      throw new Error("Attribute element must be present and not empty");
    }
    // TODO: Attribute into the response different from the Attribute into the request (103)
  }
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

    const Response = doc
      .getElementsByTagNameNS(SAML_NAMESPACE.PROTOCOL, "Response")
      .item(0);

    if (Response) {
      const IssueInstantValue = mainAttributeValidation(Response);
      const InResponseTo = Response.getAttribute("InResponseTo");
      if (!InResponseTo || InResponseTo === "") {
        throw new Error("InResponseTo must contain a non empty string");
      }
      const Destination = Response.getAttribute("Destination");
      if (!Destination || Destination === "") {
        throw new Error("Response must contain a non empty Destination");
      }
      if (Destination !== samlConfig.callbackUrl) {
        throw new Error(
          "Destination must be equalt to AssertionConsumerServiceURL"
        );
      }
      const StatusElement = Response.getElementsByTagNameNS(
        SAML_NAMESPACE.PROTOCOL,
        "Status"
      ).item(0);
      if (!StatusElement || isEmptyNode(StatusElement)) {
        throw new Error("Status element must be present");
      }
      const StatusCodeElement = StatusElement.getElementsByTagNameNS(
        SAML_NAMESPACE.PROTOCOL,
        "StatusCode"
      ).item(0);
      if (!StatusCodeElement) {
        throw new Error("StatusCode element must be present");
      }
      const StatusCodeValue = StatusCodeElement.getAttribute("Value");
      if (!StatusCodeValue || StatusCodeValue === "") {
        throw new Error("StatusCode must contain a non empty Value");
      }
      if (StatusCodeValue !== "urn:oasis:names:tc:SAML:2.0:status:Success") {
        throw new Error("Value attribute of StatusCode is invalid"); // TODO: Must be shown an error page to the user (26)
      }
      validateIssuer(Response);
      const Assertion = Response.getElementsByTagNameNS(
        SAML_NAMESPACE.ASSERTION,
        "Assertion"
      ).item(0);
      if (!Assertion) {
        throw new Error("Assertion element must be present");
      }
      const AssertionIssueInstantValue = mainAttributeValidation(Assertion);
      assertionValidation(Assertion, samlConfig, InResponseTo);
      samlConfig.cacheProvider?.get(InResponseTo, (err, value) => {
        try {
          if (err) {
            throw new Error("Error reading the cache provider");
          }
          const RequestIssueInstant = new Date(value);
          if (IssueInstantValue.getTime() < RequestIssueInstant.getTime()) {
            throw new Error(
              "Request IssueInstant must after Request IssueInstant"
            );
          }
          if (
            AssertionIssueInstantValue.getTime() < RequestIssueInstant.getTime()
          ) {
            throw new Error(
              "Assertion IssueInstant must after Request IssueInstant"
            );
          }
          callback(null, true);
        } catch (e) {
          callback(e);
        }
      });
    }
  } catch (e) {
    logger.error("Error parsing IDP response:%s", e.message);
    callback(e);
  }
};
