import { right } from "fp-ts/lib/Either";
import { isSome, tryCatch } from "fp-ts/lib/Option";
import { fromEither } from "fp-ts/lib/TaskEither";
import { SamlConfig } from "passport-saml";
import { DOMParser } from "xmldom";
import { samlRequest, samlResponse } from "../__mocks__/saml";
import { getXmlFromSamlResponse, preValidateResponse } from "../saml";
import * as saml from "../saml";

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
  afterAll(() => {
    jest.restoreAllMocks();
  });
  it("B", async () => {
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
    preValidateResponse(
      ({
        attributes: {
          attributes: {
            attributes: [
              "name",
              "fiscalNumber",
              "familyName",
              "mobilePhone",
              "email"
            ]
          }
        },
        authnContext: "https://www.spid.gov.it/SpidL2",
        callbackUrl: "http://localhost:3000/acs",
        issuer: "https://spid.agid.gov.it/cd"
      } as unknown) as SamlConfig,
      mockBody,
      mockRedisCacheProvider,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    await new Promise(resolve => {
      setTimeout(() => {
        expect(mockCallback).toBeCalledWith(null, true, expect.any(String));
        resolve();
      }, 100);
    });
  });
});
