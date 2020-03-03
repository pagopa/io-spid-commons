import { right } from "fp-ts/lib/Either";
import { isSome, tryCatch } from "fp-ts/lib/Option";
import { fromEither } from "fp-ts/lib/TaskEither";
import { SamlConfig } from "passport-saml";
import { DOMParser } from "xmldom";
import { samlRequest, samlResponse, samlResponseCIE } from "../__mocks__/saml";
import { StrictResponseValidationOptions } from "../middleware";
import { getPreValidateResponse, getXmlFromSamlResponse } from "../saml";
import * as saml from "../saml";

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
  const mockGetXmlFromSamlResponse = jest.spyOn(saml, "getXmlFromSamlResponse");
  const mockGet = jest.fn();
  const mockRedisCacheProvider = {
    get: mockGet,
    remove: jest.fn(),
    save: jest.fn()
  };

  const asyncExpectOnCallback = (callback: jest.Mock) =>
    new Promise(resolve => {
      setTimeout(() => {
        expect(callback).toBeCalledWith(null, true, expect.any(String));
        resolve();
      }, 100);
    });

  beforeEach(() => {
    jest.resetAllMocks();
  });

  afterAll(() => {
    jest.restoreAllMocks();
  });

  it("should preValidate succeded with a valid saml Response", async () => {
    const mockBody = "MOCKED BODY";
    mockGetXmlFromSamlResponse.mockImplementation(() =>
      tryCatch(() => new DOMParser().parseFromString(samlResponse))
    );
    mockGet.mockImplementation(() => {
      return fromEither(
        right({
          RequestXML: samlRequest,
          createdAt: "2020-02-26T07:27:42Z",
          idpIssuer: "http://localhost:8080"
        })
      );
    });
    const strictValidationOption: StrictResponseValidationOptions = {
      "http://localhost:8080": true
    };
    getPreValidateResponse(strictValidationOption)(
      samlConfig,
      mockBody,
      mockRedisCacheProvider,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    await asyncExpectOnCallback(mockCallback);
  });

  it("should preValidate succeded with a valid CIE saml Response", async () => {
    const mockBody = "MOCKED BODY";
    mockGetXmlFromSamlResponse.mockImplementation(() =>
      tryCatch(() => new DOMParser().parseFromString(samlResponseCIE))
    );
    // tslint:disable-next-line: no-identical-functions
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
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    await asyncExpectOnCallback(mockCallback);
  });
});
