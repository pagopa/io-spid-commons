/* eslint-disable max-lines-per-function */
/**
 * Methods used to tamper passport-saml generated SAML XML.
 *
 * SPID protocol has some peculiarities that need to be addressed
 * to make request, metadata and responses compliant.
 */
import { UTCISODateFromString } from "@pagopa/ts-commons/lib/dates";
import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import { predicate as PR } from "fp-ts";
import { difference } from "fp-ts/lib/Array";
import * as E from "fp-ts/lib/Either";
import { not, pipe } from "fp-ts/lib/function";
import * as O from "fp-ts/lib/Option";
import { Eq } from "fp-ts/lib/string";
import * as TE from "fp-ts/lib/TaskEither";
import { TaskEither } from "fp-ts/lib/TaskEither";
import { XMLSerializer } from "@xmldom/xmldom";
import { SPID_LEVELS, SPID_USER_ATTRIBUTES } from "../config";
import { EventTracker } from "../index";
import { PreValidateResponseT } from "../strategy/spid";
import { StrictResponseValidationOptions } from "./middleware";
import {
  assertionValidation,
  ISSUER_FORMAT,
  notSignedWithHmacPredicate,
  TransformError,
  transformsValidation,
  validateIssuer,
  extractAndLogTimings,
  safeXMLParseFromString,
} from "./samlUtils";
import {
  getAuthorizeRequestTamperer,
  getErrorCodeFromResponse,
  getIDFromRequest,
  getMetadataTamperer,
  getSamlIssuer,
  getSamlOptions,
  getXmlFromSamlResponse,
  isEmptyNode,
  logSamlCertExpiration,
  mainAttributeValidation,
  SAML_NAMESPACE,
  InfoNotAvailable,
} from "./samlUtils";

export {
  SAML_NAMESPACE,
  logSamlCertExpiration,
  getIDFromRequest,
  getMetadataTamperer,
  getXmlFromSamlResponse,
  getSamlOptions,
  getErrorCodeFromResponse,
  getAuthorizeRequestTamperer,
  getSamlIssuer,
  TransformError,
};

export type SamlAttributeT = keyof typeof SPID_USER_ATTRIBUTES;

export interface ISAMLError extends Error {
  readonly idpIssuer: string;
  readonly requestId: string;
}

interface IBaseOutput {
  readonly InResponseTo: NonEmptyString;
  readonly Assertion: Element;
  readonly IssueInstant: Date;
  readonly Response: Element;
  readonly AssertionIssueInstant: Date;
}

interface ISamlCacheType {
  readonly RequestXML: string;
  readonly createdAt: Date;
  readonly idpIssuer: string;
}

type IRequestAndResponseStep = IBaseOutput & {
  readonly SAMLRequestCache: ISamlCacheType;
};

type ISAMLRequest = IRequestAndResponseStep & { readonly Request: Document };

type IIssueInstant = ISAMLRequest & {
  readonly RequestIssueInstant: Date;
  readonly RequestAuthnRequest: Element;
};

export type IIssueInstantWithAuthnContextCR = IIssueInstant & {
  readonly RequestAuthnContextClassRef: NonEmptyString;
};

interface ITransformValidation {
  readonly idpIssuer: string;
  readonly message: string;
  readonly numberOfTransforms: number;
}

const ISSUER_FORMAT_ERROR = new Error(
  "Format attribute of Issuer element is invalid"
);

const hasExtraParams = <T extends Record<string, unknown>>(t: T): t is T =>
  Object.keys(t).length > 0;

const getExtraParamsOrUndefined = <T extends Record<string, unknown>>(
  t: T
): T | undefined => (hasExtraParams(t) ? t : undefined);

export const getPreValidateResponse =
  // eslint-disable-next-line prettier/prettier


    <T extends Record<string, unknown>>(
      strictValidationOptions?: StrictResponseValidationOptions,
      eventHandler?: EventTracker,
      hasClockSkewLoggingEvent?: boolean
    ): PreValidateResponseT<T> =>
    (
      samlConfig,
      body,
      extendedCacheProvider,
      doneCb,
      callback
      // eslint-disable-next-line sonarjs/cognitive-complexity
    ): void => {
      const maybeDoc = getXmlFromSamlResponse(body);
      const startTime = Date.now();

      if (O.isNone(maybeDoc)) {
        throw new Error("Empty SAML response");
      }
      const doc = maybeDoc.value;

      const responsesCollection = doc.getElementsByTagNameNS(
        SAML_NAMESPACE.PROTOCOL,
        "Response"
      );

      const maybeIdpIssuer = getSamlIssuer(doc);

      const hasStrictValidation = pipe(
        O.fromNullable(strictValidationOptions),
        O.chain((validationOptions) =>
          pipe(
            maybeIdpIssuer,
            O.chainNullableK((issuer) => validationOptions[issuer])
          )
        ),
        O.getOrElse(() => false)
      );

      const idpIssuer: string = pipe(
        maybeIdpIssuer,
        O.getOrElse(() => InfoNotAvailable)
      );

      // here we are partially validating the response just to obtain a requestId (InResponseTo) before doing any more step.
      // this is needed if we want to have to log the requestId at any step further
      const errorOrPartiallyValidatedResponse: E.Either<
        Error,
        { readonly InResponseTo: NonEmptyString; readonly Response: Element }
      > = pipe(
        responsesCollection.item(0),
        // this check is bound to the next one, because we can receive no Response based on the official validator guidelines
        E.fromNullable(
          new Error("Missing Response element inside SAML Response")
        ),
        E.chainFirst(
          E.fromPredicate(
            // updated versions of xmldom will convert any additional root node in a text node(https://github.com/advisories/GHSA-crh6-fp67-6883)
            // to ensure if more than one samlp:Response node was provided, we must check if the sibling node is present, returning an error afterwards
            ({ nextSibling }) =>
              nextSibling === null || nextSibling === undefined,
            (_) =>
              new Error("SAML Response must have only one Response element")
          )
        ),
        E.chain((Response) =>
          pipe(
            NonEmptyString.decode(Response.getAttribute("InResponseTo")),
            E.mapLeft(
              () => new Error("InResponseTo must contain a non empty string")
            ),
            E.map((InResponseTo) => ({ InResponseTo, Response }))
          )
        )
      );

      const requestId: string = pipe(
        errorOrPartiallyValidatedResponse,
        E.map(({ InResponseTo }) => InResponseTo),
        E.getOrElse(() => InfoNotAvailable)
      );

      const responseElementValidationStep: TaskEither<Error, IBaseOutput> =
        TE.fromEither(
          pipe(
            errorOrPartiallyValidatedResponse,
            E.chainW(({ Response, InResponseTo }) =>
              pipe(
                mainAttributeValidation(startTime)(
                  Response,
                  samlConfig.acceptedClockSkewMs
                ),
                E.map((IssueInstant) => ({
                  InResponseTo,
                  IssueInstant,
                  Response,
                }))
              )
            ),
            E.chain((_) =>
              pipe(
                NonEmptyString.decode(_.Response.getAttribute("Destination")),
                E.mapLeft(
                  () =>
                    new Error("Response must contain a non empty Destination")
                ),
                E.chain(
                  E.fromPredicate(
                    (Destination) => Destination === samlConfig.callbackUrl,
                    () =>
                      new Error(
                        "Destination must be equal to AssertionConsumerServiceURL"
                      )
                  )
                ),
                E.map(() => _)
              )
            ),
            E.chain((_) =>
              pipe(
                E.fromOption(() => new Error("Status element must be present"))(
                  O.fromNullable(
                    _.Response.getElementsByTagNameNS(
                      SAML_NAMESPACE.PROTOCOL,
                      "Status"
                    ).item(0)
                  )
                ),
                E.mapLeft(
                  () =>
                    new Error("Status element must be present into Response")
                ),
                E.chain(
                  E.fromPredicate(
                    not(isEmptyNode),
                    () => new Error("Status element must be present not empty")
                  )
                ),
                E.chain((Status) =>
                  E.fromOption(
                    () => new Error("StatusCode element must be present")
                  )(
                    O.fromNullable(
                      Status.getElementsByTagNameNS(
                        SAML_NAMESPACE.PROTOCOL,
                        "StatusCode"
                      ).item(0)
                    )
                  )
                ),
                E.chain((StatusCode) =>
                  pipe(
                    E.fromOption(
                      () =>
                        new Error("StatusCode must contain a non empty Value")
                    )(O.fromNullable(StatusCode.getAttribute("Value"))),
                    E.chain((statusCode) =>
                      // TODO: Must show an error page to the user (26)
                      pipe(
                        statusCode,
                        E.fromPredicate(
                          (Value) =>
                            Value.toLowerCase() ===
                            "urn:oasis:names:tc:SAML:2.0:status:Success".toLowerCase(),
                          () =>
                            new Error(
                              `Value attribute of StatusCode is invalid: ${statusCode}`
                            )
                        )
                      )
                    ),
                    E.map(() => _)
                  )
                )
              )
            ),
            E.chain(
              E.fromPredicate(
                (predicate) =>
                  predicate.Response.getElementsByTagNameNS(
                    SAML_NAMESPACE.ASSERTION,
                    "EncryptedAssertion"
                  ).length === 0,
                (_) => new Error("EncryptedAssertion element is forbidden")
              )
            ),
            E.chain((p) =>
              pipe(
                notSignedWithHmacPredicate(p.Response),
                E.map((_) => p)
              )
            ),
            E.chain(
              E.fromPredicate(
                (predicate) =>
                  predicate.Response.getElementsByTagNameNS(
                    SAML_NAMESPACE.ASSERTION,
                    "Assertion"
                  ).length < 2,
                (_) =>
                  new Error(
                    "SAML Response must have only one Assertion element"
                  )
              )
            ),
            E.chain((_) =>
              pipe(
                E.fromOption(
                  () => new Error("Assertion element must be present")
                )(
                  O.fromNullable(
                    _.Response.getElementsByTagNameNS(
                      SAML_NAMESPACE.ASSERTION,
                      "Assertion"
                    ).item(0)
                  )
                ),
                E.map((assertion) => ({ ..._, Assertion: assertion }))
              )
            ),
            E.chain((_) =>
              pipe(
                mainAttributeValidation(startTime)(
                  _.Assertion,
                  samlConfig.acceptedClockSkewMs
                ),
                E.map((IssueInstant) => ({
                  AssertionIssueInstant: IssueInstant,
                  ..._,
                }))
              )
            )
          )
        );

      const returnRequestAndResponseStep = (
        _: IBaseOutput
      ): TaskEither<Error, IRequestAndResponseStep> =>
        pipe(
          extendedCacheProvider.get(_.InResponseTo),
          TE.map((SAMLRequestCache) => {
            const {
              // eslint-disable-next-line @typescript-eslint/no-unused-vars
              RequestXML,
              // eslint-disable-next-line @typescript-eslint/no-unused-vars
              createdAt,
              // eslint-disable-next-line @typescript-eslint/no-unused-vars
              idpIssuer: _idpIssuer,
              ...extraLoginRequestParams
            } = SAMLRequestCache;

            return {
              ..._,
              SAMLRequestCache,
              // Cast needed to bypass Omit type inference
              extraLoginRequestParams: extraLoginRequestParams as T,
            };
          }),
          TE.map(
            (__) => (
              doneCb &&
                O.tryCatch(() =>
                  doneCb(
                    __.SAMLRequestCache.RequestXML,
                    new XMLSerializer().serializeToString(doc),
                    getExtraParamsOrUndefined(__.extraLoginRequestParams)
                  )
                ),
              __
            )
          )
        );

      const parseSAMLRequestStep = (
        _: IRequestAndResponseStep
      ): TaskEither<Error, ISAMLRequest> =>
        pipe(
          TE.fromEither(
            pipe(
              _.SAMLRequestCache.RequestXML,
              safeXMLParseFromString,
              E.fromOption(
                () =>
                  new Error("An error occurs parsing the cached SAML Request")
              )
            )
          ),
          TE.map((Request) => ({ ..._, Request }))
        );

      const getIssueInstantFromRequestStep = (
        _: ISAMLRequest
      ): TaskEither<Error, IIssueInstant> =>
        pipe(
          TE.fromEither(
            E.fromOption(
              () => new Error("Missing AuthnRequest into Cached Request")
            )(
              O.fromNullable(
                _.Request.getElementsByTagNameNS(
                  SAML_NAMESPACE.PROTOCOL,
                  "AuthnRequest"
                ).item(0)
              )
            )
          ),
          TE.map((RequestAuthnRequest) => ({ ..._, RequestAuthnRequest })),
          TE.chain((__) =>
            pipe(
              TE.fromEither(
                pipe(
                  UTCISODateFromString.decode(
                    __.RequestAuthnRequest.getAttribute("IssueInstant")
                  ),
                  E.mapLeft(
                    () =>
                      new Error(
                        "IssueInstant into the Request must be a valid UTC string"
                      )
                  )
                )
              ),
              TE.map((RequestIssueInstant) => ({ ...__, RequestIssueInstant }))
            )
          )
        );

      const issueInstantValidationStep = (
        _: IIssueInstant
      ): TaskEither<Error, IIssueInstant> =>
        pipe(
          TE.fromEither(
            pipe(
              _.RequestIssueInstant,
              E.fromPredicate(
                (_1) => _1.getTime() <= _.IssueInstant.getTime(),
                () =>
                  new Error(
                    "Response IssueInstant must after Request IssueInstant"
                  )
              )
            )
          ),
          TE.map(() => _)
        );

      const assertionIssueInstantValidationStep = (
        _: IIssueInstant
      ): TaskEither<Error, IIssueInstant> =>
        pipe(
          TE.fromEither(
            pipe(
              _.RequestIssueInstant,
              E.fromPredicate(
                (_1) => _1.getTime() <= _.AssertionIssueInstant.getTime(),
                () =>
                  new Error(
                    "Assertion IssueInstant must after Request IssueInstant"
                  )
              )
            )
          ),
          TE.map(() => _)
        );

      const authnContextClassRefValidationStep = (
        _: IIssueInstant
      ): TaskEither<Error, IIssueInstantWithAuthnContextCR> =>
        TE.fromEither(
          pipe(
            E.fromOption(
              () =>
                new Error(
                  "Missing AuthnContextClassRef inside cached SAML Response"
                )
            )(
              O.fromNullable(
                _.RequestAuthnRequest.getElementsByTagNameNS(
                  SAML_NAMESPACE.ASSERTION,
                  "AuthnContextClassRef"
                ).item(0)
              )
            ),
            E.chain(
              E.fromPredicate(
                PR.not(isEmptyNode),
                () => new Error("Subject element must be not empty")
              )
            ),
            E.chain((RequestAuthnContextClassRef) =>
              pipe(
                NonEmptyString.decode(
                  RequestAuthnContextClassRef.textContent?.trim()
                ),
                E.mapLeft(
                  () =>
                    new Error(
                      "AuthnContextClassRef inside cached Request must be a non empty string"
                    )
                )
              )
            ),
            E.chain(
              E.fromPredicate(
                (reqAuthnContextClassRef) =>
                  reqAuthnContextClassRef === SPID_LEVELS.SpidL1 ||
                  reqAuthnContextClassRef === SPID_LEVELS.SpidL2 ||
                  reqAuthnContextClassRef === SPID_LEVELS.SpidL3,
                () => new Error("Unexpected Request authnContextClassRef value")
              )
            ),
            E.map((rACCR) => ({
              ..._,
              RequestAuthnContextClassRef: rACCR,
            }))
          )
        );

      const attributesValidationStep = (
        _: IIssueInstantWithAuthnContextCR
      ): TaskEither<Error, IIssueInstantWithAuthnContextCR> =>
        pipe(
          TE.fromEither(
            assertionValidation(startTime)(
              _.Assertion,
              samlConfig,
              _.InResponseTo,
              _.RequestAuthnContextClassRef
            )
          ),
          TE.chain((Attributes) => {
            if (!hasStrictValidation) {
              // Skip Attribute validation if IDP has non-strict validation option
              return TE.right(Attributes);
            }
            const missingAttributes = difference(Eq)(
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              (samlConfig as any).attributes?.attributes?.attributes || [
                "Request attributes must be defined",
              ],
              Array.from(Attributes).reduce((prev, attr) => {
                const attribute = attr.getAttribute("Name");
                if (attribute) {
                  return [...prev, attribute];
                }
                return prev;
              }, new Array<string>())
            );
            return TE.fromEither(
              E.fromPredicate(
                () => missingAttributes.length === 0,
                () =>
                  new Error(
                    `Missing required Attributes: ${missingAttributes.toString()}`
                  )
              )(Attributes)
            );
          }),
          TE.map(() => _)
        );

      const responseIssuerValidationStep = (
        _: IIssueInstantWithAuthnContextCR
      ): TaskEither<Error, IIssueInstantWithAuthnContextCR> =>
        pipe(
          TE.fromEither(
            pipe(
              validateIssuer(_.Response, _.SAMLRequestCache.idpIssuer),
              E.chainW((Issuer) =>
                pipe(
                  E.fromOption(() => "Format missing")(
                    O.fromNullable(Issuer.getAttribute("Format"))
                  ),
                  E.mapLeft(() => E.right(_)),
                  E.map((_1) =>
                    E.fromPredicate(
                      (FormatValue) =>
                        !FormatValue || FormatValue === ISSUER_FORMAT,
                      () => ISSUER_FORMAT_ERROR
                    )(_1)
                  ),
                  E.map(() => E.right(_)),
                  E.toUnion
                )
              )
            )
          ),
          TE.map(() => _)
        );

      const assertionIssuerValidationStep = (
        _: IIssueInstantWithAuthnContextCR
      ): TaskEither<Error, IIssueInstantWithAuthnContextCR> =>
        pipe(
          TE.fromEither(
            pipe(
              validateIssuer(_.Assertion, _.SAMLRequestCache.idpIssuer),
              E.chain((Issuer) =>
                pipe(
                  NonEmptyString.decode(Issuer.getAttribute("Format")),
                  E.mapLeft(
                    () =>
                      new Error(
                        "Format attribute of Issuer element must be a non empty string into Assertion"
                      )
                  ),
                  E.chain(
                    E.fromPredicate(
                      (Format) => Format === ISSUER_FORMAT,
                      () => ISSUER_FORMAT_ERROR
                    )
                  ),
                  E.fold(
                    (err) =>
                      // Skip Issuer Format validation if IDP has non-strict validation option
                      !hasStrictValidation ? E.right(_) : E.left(err),
                    (_1) => E.right(_)
                  )
                )
              )
            )
          ),
          TE.map(() => _)
        );

      const transformValidationStep = (
        _: IIssueInstantWithAuthnContextCR
      ): TaskEither<ITransformValidation, IIssueInstantWithAuthnContextCR> =>
        pipe(
          TE.fromEither(
            transformsValidation(_.Response, _.SAMLRequestCache.idpIssuer)
          ),
          TE.map(() => _)
        );

      /* LOGGING INFOS:
       * having the idpIssuer and requestId as data here we leverage multiple advantages:
       * 1. we can query based on the idp and display graphs about errors/usage
       * 2. we know what idp is causing the error
       * 3. having the requestId it's possible to analyze further the problem encountered
       */
      const validationFailure = (error: Error | ITransformValidation): void => {
        if (eventHandler) {
          if (TransformError.is(error)) {
            eventHandler({
              data: {
                idpIssuer: error.idpIssuer,
                message: error.message,
                numberOfTransforms: String(error.numberOfTransforms),
                requestId,
              },
              name: "spid.error.transformOccurenceOverflow",
              type: "ERROR",
            });
          } else {
            eventHandler({
              data: {
                idpIssuer,
                message: error.message,
                requestId,
              },
              name: "spid.error.generic",
              type: "ERROR",
            });
          }
        }
        return callback(E.toError(error.message));
      };

      const validationSuccess = (_: IIssueInstantWithAuthnContextCR): void => {
        // Number of the Response signature.
        // Calculated as number of the Signature elements inside the document minus number of the Signature element of the Assertion.
        const signatureOfResponseCount =
          _.Response.getElementsByTagNameNS(SAML_NAMESPACE.XMLDSIG, "Signature")
            .length -
          _.Assertion.getElementsByTagNameNS(
            SAML_NAMESPACE.XMLDSIG,
            "Signature"
          ).length;
        // For security reasons it is preferable that the Response be signed.
        // According to the technical rules of SPID, the signature of the Response is optional @ref https://docs.italia.it/italia/spid/spid-regole-tecniche/it/stabile/single-sign-on.html#response.
        // Here we collect data when an IDP sends an unsigned Response.
        // If all IDPs sign it, we can safely request it as mandatory @ref https://www.pivotaltracker.com/story/show/174710289.
        if (eventHandler && signatureOfResponseCount === 0) {
          eventHandler({
            data: {
              idpIssuer: _.SAMLRequestCache.idpIssuer,
              message: "Missing Request signature",
              requestId: _.InResponseTo,
            },
            name: "spid.error.signature",
            type: "INFO",
          });
        }
        return callback(null, true, _.InResponseTo);
      };

      pipe(
        responseElementValidationStep,
        TE.chain(returnRequestAndResponseStep),
        TE.chain(parseSAMLRequestStep),
        TE.chain(getIssueInstantFromRequestStep),
        TE.chainFirst(issueInstantValidationStep),
        TE.chainFirst(assertionIssueInstantValidationStep),
        TE.chain(authnContextClassRefValidationStep),
        TE.chainFirst(attributesValidationStep),
        TE.chainFirst(responseIssuerValidationStep),
        TE.chainFirst(assertionIssuerValidationStep),
        TE.chainFirstW(transformValidationStep),
        // log timings infos
        TE.chainFirstW(
          extractAndLogTimings(
            startTime,
            idpIssuer,
            requestId,
            samlConfig.acceptedClockSkewMs,
            eventHandler,
            hasClockSkewLoggingEvent
          )
        ),
        TE.bimap(validationFailure, validationSuccess)
      )().catch(callback);
    };
