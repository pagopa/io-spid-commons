import { right, toError } from "fp-ts/lib/Either";
import { isSome, tryCatch } from "fp-ts/lib/Option";
import { fromEither } from "fp-ts/lib/TaskEither";
import { SamlConfig } from "passport-saml";
import { DOMParser } from "xmldom";
import { EventTracker } from "../../index";
import {
  getSamlAssertion,
  getSamlResponse,
  samlEncryptedAssertion,
  samlRequest,
  samlResponseCIE
} from "../__mocks__/saml";
import { StrictResponseValidationOptions } from "../middleware";
import {
  getPreValidateResponse,
  getXmlFromSamlResponse,
  TransformError
} from "../saml";
import * as saml from "../samlUtils";

const samlConfig: SamlConfig = ({
  attributes: {
    attributes: {
      attributes: ["name", "fiscalNumber", "familyName", "mobilePhone", "email"]
    }
  },
  authnContext: "https://www.spid.gov.it/SpidL2",
  callbackUrl: "https://app-backend.dev.io.italia.it/assertionConsumerService",
  issuer: "https://app-backend.dev.io.italia.it"
} as unknown) as SamlConfig;

const hMacSignatureMethod = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
const aResponseSignedWithHMAC = getSamlResponse({
  signatureMethod: hMacSignatureMethod
});
const aResponseWithOneAssertionSignedWithHMAC = getSamlResponse({
  customAssertion: getSamlAssertion(0, hMacSignatureMethod)
});
const aResponseSignedWithHMACWithOneAssertionSignedWithHMAC = getSamlResponse({
  customAssertion: getSamlAssertion(0, hMacSignatureMethod),
  signatureMethod: hMacSignatureMethod
});

describe("getXmlFromSamlResponse", () => {
  it("should parse a well formatted response body", () => {
    const expectedSAMLResponse = "<xml>Response</xml>";
    const responseBody = {
      SAMLResponse: Buffer.from(expectedSAMLResponse).toString("base64")
    };
    const responseDocument = getXmlFromSamlResponse(responseBody);
    expect(isSome(responseDocument)).toBeTruthy();
  });
});

describe("preValidateResponse", () => {
  const mockCallback = jest.fn();
  const mockGetXmlFromSamlResponse = jest
    .spyOn(saml, "getXmlFromSamlResponse")
    .mockImplementation(() =>
      tryCatch(() => new DOMParser().parseFromString(getSamlResponse()))
    );
  const mockGet = jest.fn();
  const mockRedisCacheProvider = {
    get: mockGet,
    remove: jest.fn(),
    save: jest.fn()
  };
  const mockBody = "MOCKED BODY";
  const mockTestIdpIssuer = "http://localhost:8080";

  const mockEventTracker = jest.fn() as EventTracker;

  const expectedDesynResponseValueMs = 2000;

  const expectedGenericEventName = "spid.error.generic";
  const expectedTransformEventName = "spid.error.transformOccurenceOverflow";
  const expectedSignatureErrorName = "spid.error.signature";

  const asyncExpectOnCallback = (
    callback: jest.Mock,
    error?: Error | TransformError
  ) =>
    new Promise(resolve => {
      setTimeout(() => {
        error
          ? expect(callback).toBeCalledWith(toError(error.message))
          : expect(callback).toBeCalledWith(null, true, expect.any(String));
        resolve(void 0);
      }, 100);
    });

  beforeEach(() => {
    jest.resetAllMocks();
    mockGet.mockImplementation(() => {
      return fromEither(
        right({
          RequestXML: samlRequest,
          createdAt: "2020-02-26T07:27:42Z",
          idpIssuer: mockTestIdpIssuer
        })
      );
    });
  });

  afterAll(() => {
    jest.restoreAllMocks();
  });

  it("should preValidate fail when saml Response has multiple Assertion elements", async () => {
    mockGetXmlFromSamlResponse.mockImplementationOnce(() =>
      tryCatch(() =>
        new DOMParser().parseFromString(
          getSamlResponse({ customAssertion: getSamlAssertion().repeat(2) })
        )
      )
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption, mockEventTracker)(
      { ...samlConfig, acceptedClockSkewMs: 0 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    const expectedError = new Error(
      "SAML Response must have only one Assertion element"
    );
    await asyncExpectOnCallback(mockCallback, expectedError);
    expect(mockEventTracker).toBeCalledWith({
      data: {
        message: expectedError.message,
        requestId: expect.any(String),
        idpIssuer: expect.any(String)
      },
      name: expectedGenericEventName,
      type: "ERROR"
    });
  });

  it("should preValidate fail when saml Response has EncryptedAssertion element", async () => {
    mockGetXmlFromSamlResponse.mockImplementationOnce(() =>
      tryCatch(() =>
        new DOMParser().parseFromString(
          getSamlResponse({ customAssertion: samlEncryptedAssertion })
        )
      )
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption, mockEventTracker)(
      { ...samlConfig, acceptedClockSkewMs: 2000 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    const expectedError = new Error("EncryptedAssertion element is forbidden");
    await asyncExpectOnCallback(mockCallback, expectedError);
    expect(mockEventTracker).toBeCalledWith({
      data: {
        message: expectedError.message,
        requestId: expect.any(String),
        idpIssuer: expect.any(String)
      },
      name: expectedGenericEventName,
      type: "ERROR"
    });
  });

  it("should preValidate fail when saml Response has multiple Response elements", async () => {
    mockGetXmlFromSamlResponse.mockImplementationOnce(() =>
      tryCatch(() =>
        new DOMParser().parseFromString(getSamlResponse().repeat(2))
      )
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption, mockEventTracker)(
      { ...samlConfig, acceptedClockSkewMs: 0 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    const expectedError = new Error(
      "SAML Response must have only one Response element"
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    await asyncExpectOnCallback(mockCallback, expectedError);
    expect(mockEventTracker).toBeCalledWith({
      data: {
        message: expectedError.message,
        requestId: expect.any(String),
        idpIssuer: expect.any(String)
      },
      name: expectedGenericEventName,
      type: "ERROR"
    });
  });

  it("should preValidate fail when saml response has more than 4 Transform (4 Assertion + 2 Response) elements in SignedInfo", async () => {
    mockGetXmlFromSamlResponse.mockImplementationOnce(() =>
      tryCatch(() =>
        new DOMParser().parseFromString(
          getSamlResponse({
            customAssertion: getSamlAssertion(
              0,
              "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
              2
            )
          })
        )
      )
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption, mockEventTracker)(
      { ...samlConfig, acceptedClockSkewMs: 0 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    const expectedError = TransformError.encode({
      idpIssuer: mockTestIdpIssuer,
      message: "Transform element cannot occurs more than 4 times",
      numberOfTransforms: 6
    });
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    await asyncExpectOnCallback(mockCallback, expectedError);
    expect(mockEventTracker).toBeCalledWith({
      data: {
        idpIssuer: expectedError.idpIssuer,
        message: expectedError.message,
        numberOfTransforms: String(expectedError.numberOfTransforms),
        requestId: expect.any(String)
      },
      name: expectedTransformEventName,
      type: "ERROR"
    });
  });
  it("should preValidate fail when saml response has more than 4 Transform elements (4 Response + 2 Assertion) in SignedInfo", async () => {
    mockGetXmlFromSamlResponse.mockImplementationOnce(() =>
      tryCatch(() =>
        new DOMParser().parseFromString(
          getSamlResponse({ repeatTransforms: 2 })
        )
      )
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption, mockEventTracker)(
      { ...samlConfig, acceptedClockSkewMs: 0 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    const expectedError = TransformError.encode({
      idpIssuer: mockTestIdpIssuer,
      message: "Transform element cannot occurs more than 4 times",
      numberOfTransforms: 6
    });
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    await asyncExpectOnCallback(mockCallback, expectedError);
    expect(mockEventTracker).toBeCalledWith({
      data: {
        idpIssuer: expectedError.idpIssuer,
        message: expectedError.message,
        numberOfTransforms: String(expectedError.numberOfTransforms),
        requestId: expect.any(String)
      },
      name: expectedTransformEventName,
      type: "ERROR"
    });
  });

  it("should preValidate succeded with a valid saml Response", async () => {
    mockGetXmlFromSamlResponse.mockImplementationOnce(() =>
      tryCatch(() => new DOMParser().parseFromString(getSamlResponse()))
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption)(
      { ...samlConfig, acceptedClockSkewMs: 0 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    await asyncExpectOnCallback(mockCallback);
  });

  it("should preValidate succeded and send an Event on valid Response with missing Signature", async () => {
    mockGetXmlFromSamlResponse.mockImplementationOnce(() =>
      tryCatch(() =>
        new DOMParser().parseFromString(
          getSamlResponse({ hasResponseSignature: false })
        )
      )
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption, mockEventTracker)(
      { ...samlConfig, acceptedClockSkewMs: 0 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    await asyncExpectOnCallback(mockCallback);
    expect(mockEventTracker).toBeCalledWith({
      data: {
        idpIssuer: mockTestIdpIssuer,
        message: expect.any(String),
        requestId: expect.any(String)
      },
      name: expectedSignatureErrorName,
      type: "INFO"
    });
  });

  it("should preValidate succeed if timers are desynchronized and acceptedClockSkewMs is disabled", async () => {
    mockGetXmlFromSamlResponse.mockImplementationOnce(() =>
      tryCatch(() =>
        new DOMParser().parseFromString(
          getSamlResponse({ clockSkewMs: expectedDesynResponseValueMs })
        )
      )
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption)(
      { ...samlConfig, acceptedClockSkewMs: -1 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    await asyncExpectOnCallback(mockCallback);
  });

  it("should preValidate succeed if timers desync is less than acceptedClockSkewMs", async () => {
    mockGetXmlFromSamlResponse.mockImplementationOnce(() =>
      tryCatch(() =>
        new DOMParser().parseFromString(
          getSamlResponse({ clockSkewMs: expectedDesynResponseValueMs })
        )
      )
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption)(
      { ...samlConfig, acceptedClockSkewMs: 2000 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    await asyncExpectOnCallback(mockCallback);
  });

  it("should preValidate succeed and log the timing deltas when hasClockSkewLoggingEvent is provided", async () => {
    mockGetXmlFromSamlResponse.mockImplementationOnce(() =>
      tryCatch(() => new DOMParser().parseFromString(getSamlResponse()))
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption, mockEventTracker, true)(
      { ...samlConfig, acceptedClockSkewMs: 0 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    await asyncExpectOnCallback(mockCallback);

    expect(mockEventTracker).toHaveBeenCalledTimes(1);
    expect(mockEventTracker).toHaveBeenCalledWith(
      expect.objectContaining({
        data: {
          idpIssuer: expect.any(String),
          message: "Clockskew validations logging",
          requestId: expect.any(String),
          AssertionConditionsNotOnOrAfterClockSkew: expect.any(String),
          AssertionIssueInstantClockSkew: expect.any(String),
          AssertionNotBeforeClockSkew: expect.any(String),
          AssertionSubjectNotOnOrAfterClockSkew: expect.any(String),
          ResponseIssueInstantClockSkew: expect.any(String)
        },
        name: "spid.info.clockskew",
        type: "INFO"
      })
    );
  });

  it("should preValidate fail if timer desync exceeds acceptedClockSkewMs", async () => {
    mockGetXmlFromSamlResponse.mockImplementationOnce(() =>
      tryCatch(() =>
        new DOMParser().parseFromString(
          getSamlResponse({ clockSkewMs: expectedDesynResponseValueMs })
        )
      )
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption)(
      {
        ...samlConfig,
        acceptedClockSkewMs: expectedDesynResponseValueMs - 100
      },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    await asyncExpectOnCallback(
      mockCallback,
      new Error("IssueInstant must be in the past")
    );
  });

  it.each`
    title                                                                                            | response
    ${"uses HMAC as signature algorithm"}                                                            | ${aResponseSignedWithHMAC}
    ${"has an assertion that uses HMAC as signature algorithm"}                                      | ${aResponseWithOneAssertionSignedWithHMAC}
    ${"uses HMAC as signature algorithm and has an assertion that uses HMAC as signature algorithm"} | ${aResponseSignedWithHMACWithOneAssertionSignedWithHMAC}
  `(
    "should preValidate fail when saml Response $title",
    async ({ response }) => {
      mockGetXmlFromSamlResponse.mockImplementationOnce(() =>
        tryCatch(() => new DOMParser().parseFromString(response))
      );
      const strictValidationOption: StrictResponseValidationOptions = {
        mockTestIdpIssuer: true
      };
      getPreValidateResponse(strictValidationOption, mockEventTracker)(
        { ...samlConfig, acceptedClockSkewMs: 0 },
        mockBody,
        mockRedisCacheProvider,
        undefined,
        mockCallback
      );
      expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
      const expectedError = new Error("HMAC Signature is forbidden");
      await asyncExpectOnCallback(mockCallback, expectedError);
      expect(mockEventTracker).toBeCalledWith({
        data: {
          message: expectedError.message,
          requestId: expect.any(String),
          idpIssuer: expect.any(String)
        },
        name: expectedGenericEventName,
        type: "ERROR"
      });
    }
  );

  describe("preValidateResponse with CIE saml Response", () => {
    beforeEach(() => {
      jest.resetAllMocks();
    });

    it("should preValidate succeded with a valid CIE saml Response", async () => {
      mockGetXmlFromSamlResponse.mockImplementationOnce(() =>
        tryCatch(() => new DOMParser().parseFromString(samlResponseCIE))
      );
      mockGet.mockImplementation(() => {
        return fromEither(
          right({
            RequestXML: samlRequest,
            createdAt: "2020-02-26T07:27:42Z",
            idpIssuer:
              "https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/POST/SSO"
          })
        );
      });
      getPreValidateResponse()(
        samlConfig,
        mockBody,
        mockRedisCacheProvider,
        undefined,
        mockCallback
      );
      expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
      await asyncExpectOnCallback(mockCallback);
    });
  });

  it("should preValidate fail when saml Response uses HMAC as signature algorithm", async () => {
    mockGetXmlFromSamlResponse.mockImplementationOnce(() =>
      tryCatch(() =>
        new DOMParser().parseFromString(
          getSamlResponse({
            signatureMethod: hMacSignatureMethod
          })
        )
      )
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption, mockEventTracker)(
      { ...samlConfig, acceptedClockSkewMs: 0 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    const expectedError = new Error("HMAC Signature is forbidden");
    await asyncExpectOnCallback(mockCallback, expectedError);
    expect(mockEventTracker).toBeCalledWith({
      data: {
        message: expectedError.message,
        requestId: expect.any(String),
        idpIssuer: expect.any(String)
      },
      name: expectedGenericEventName,
      type: "ERROR"
    });
  });
});
