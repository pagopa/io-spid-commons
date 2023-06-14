import * as jose from "jose";
import * as t from "io-ts";
import { left, right } from "fp-ts/lib/Either";
import { fromEither } from "fp-ts/lib/TaskEither";
import { Builder, parseStringPromise } from "xml2js";
import mockReq from "../../__mocks__/request";
import { IServiceProviderConfig } from "../../utils/middleware";
import { getAuthorizeRequestTamperer } from "../../utils/saml";
import { mockWrapCallback } from "../__mocks__/passport-saml";
import {
  SAMLRequestCacheItem,
  getExtendedRedisCacheProvider,
} from "../redis_cache_provider";
import { CustomSamlClient } from "../saml_client";
import {
  DEFAULT_LOLLIPOP_HASH_ALGORITHM,
  LOLLIPOP_PUB_KEY_HEADER_NAME,
} from "../../types/lollipop";
import { JwkPublicKey } from "@pagopa/ts-commons/lib/jwk";
import { samlRequest, samlRequestWithID } from "../../utils/__mocks__/saml";
import { pipe } from "fp-ts/lib/function";
import * as TE from "fp-ts/lib/TaskEither";
import * as E from "fp-ts/Either";
import { RedisClientType } from "@redis/client";
import { SamlConfig } from "../..";
import { expectedExtraParams } from "../../__mocks__/extraParams";

const expectedRequestID = "123456";
const SAMLRequest = `<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="${expectedRequestID}" Version="2.0" 
  IssueInstant="2020-02-17T10:20:28.417Z"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Destination="http://localhost:8080/samlsso" ForceAuthn="true" 
  AssertionConsumerServiceURL="http://localhost:3000/acs" AttributeConsumingServiceIndex="0">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    NameQualifier="https://spid.agid.gov.it/cd" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://spid.agid.gov.it/cd</saml:Issuer>
  <samlp:NameIDPolicy xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>
  <samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Comparison="exact">
  <saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://www.spid.gov.it/SpidL2</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>`;

const samlConfig: SamlConfig = {
  idpIssuer: "http://localhost:8080/",
};

const mockSetEx = jest.fn();
const mockGet = jest.fn();
const mockDel = jest.fn();

const mockRedisClient = {} as RedisClientType;
mockRedisClient.setEx = mockSetEx;
mockRedisClient.get = mockGet;
mockRedisClient.del = mockDel;

const expectedRequestData: SAMLRequestCacheItem = {
  RequestXML: SAMLRequest,
  createdAt: new Date(),
  idpIssuer: samlConfig.idpIssuer as string,
};
mockGet.mockImplementation(async (_) => JSON.stringify(expectedRequestData));

const redisCacheProvider = getExtendedRedisCacheProvider(
  mockRedisClient as unknown as any
);

const serviceProviderConfig: IServiceProviderConfig = {
  IDPMetadataUrl:
    "https://registry.spid.gov.it/metadata/idp/spid-entities-idps.xml",
  organization: {
    URL: "https://example.com",
    displayName: "Organization display name",
    name: "Organization name",
  },
  publicCert: "",
  requiredAttributes: {
    attributes: [
      "address",
      "email",
      "name",
      "familyName",
      "fiscalNumber",
      "mobilePhone",
    ],
    name: "Required attrs",
  },
  spidCieUrl: "https://idserver.servizicie.interno.gov.it:8443/idp/shibboleth",
  spidCieTestUrl:
    "https://collaudo.idserver.servizicie.interno.gov.it/idp/shibboleth",
  spidTestEnvUrl: "https://spid-testenv2:8088",
  spidValidatorUrl: "http://localhost:8080",
};

const authReqTampener = getAuthorizeRequestTamperer(
  // spid-testenv does not accept an xml header with utf8 encoding
  new Builder({ xmldec: { encoding: undefined, version: "1.0" } }),
  {}
);

const mockedCallback = jest.fn();

const aJwkPubKey: JwkPublicKey = {
  kty: "EC",
  crv: "secp256k1",
  x: "Q8K81dZcC4DdKl52iW7bT0ubXXm2amN835M_v5AgpSE",
  y: "lLsw82Q414zPWPluI5BmdKHK6XbFfinc8aRqbZCEv0A",
};

describe("SAML prototype arguments check", () => {
  let OriginalPassportSaml: any;
  beforeAll(() => {
    OriginalPassportSaml = jest.requireActual("passport-saml");
  });
  afterAll(() => {
    jest.restoreAllMocks();
  });

  it("should SAML constructor has 2 parameters", () => {
    expect(OriginalPassportSaml.SAML.prototype.constructor).toHaveLength(1);
  });
  it("should SAML validatePostResponse has 2 parameters", () => {
    expect(
      OriginalPassportSaml.SAML.prototype.validatePostResponse
    ).toHaveLength(2);
  });
  it("should SAML generateAuthorizeRequest has 4 parameters", () => {
    expect(
      OriginalPassportSaml.SAML.prototype.generateAuthorizeRequest
    ).toHaveLength(4);
  });
});

describe("CustomSamlClient#constructor", () => {
  afterEach(() => {
    jest.resetAllMocks();
  });

  it("should CustomSamlClient constructor call SAML constructor with overrided validateInResponseTo", () => {
    const customSamlClient = new CustomSamlClient(
      { validateInResponseTo: true },
      redisCacheProvider,
      undefined
    );
    expect(customSamlClient).toBeTruthy();

    expect(customSamlClient["options"]).toHaveProperty(
      "validateInResponseTo",
      false
    );
  });
});

describe("CustomSamlClient#validatePostResponse", () => {
  afterEach(() => {
    jest.resetAllMocks();
  });

  it("should validatePostResponse call SAML validatePostResponse", () => {
    const customSamlClient = new CustomSamlClient(
      { validateInResponseTo: true },
      redisCacheProvider,
      undefined
    );
    expect(customSamlClient).toBeTruthy();
    customSamlClient.validatePostResponse({ SAMLResponse: "" }, mockedCallback);
    expect(mockedCallback).toBeCalledTimes(1);
  });

  it("should validatePostResponse calls preValidateResponse if provided into CustomSamlClient", () => {
    const mockPreValidate = jest
      .fn()
      .mockImplementation((_, __, ___, ____, callback) => {
        callback();
      });
    const customSamlClient = new CustomSamlClient(
      { validateInResponseTo: true },
      redisCacheProvider,
      undefined,
      authReqTampener,
      mockPreValidate
    );
    expect(customSamlClient).toBeTruthy();
    customSamlClient.validatePostResponse({ SAMLResponse: "" }, mockedCallback);
    expect(mockPreValidate).toBeCalledWith(
      { validateInResponseTo: true },
      { SAMLResponse: "" },
      redisCacheProvider,
      undefined,
      expect.any(Function)
    );
    expect(mockedCallback).toBeCalledTimes(1);
  });

  it("should preValidateResponse forward the error when occours", () => {
    const expectedPreValidateError = new Error("PreValidateError");
    const mockPreValidate = jest
      .fn()
      .mockImplementation((_, __, ___, ____, callback) => {
        callback(expectedPreValidateError);
      });
    const customSamlClient = new CustomSamlClient(
      { validateInResponseTo: true },
      redisCacheProvider,
      undefined,
      authReqTampener,
      mockPreValidate
    );
    expect(customSamlClient).toBeTruthy();
    customSamlClient.validatePostResponse({ SAMLResponse: "" }, mockedCallback);
    expect(mockPreValidate).toBeCalledWith(
      { validateInResponseTo: true },
      { SAMLResponse: "" },
      redisCacheProvider,
      undefined,
      expect.any(Function)
    );
    expect(mockedCallback).toBeCalledWith(expectedPreValidateError);
    expect(mockedCallback).toBeCalledTimes(1);
  });

  it("should remove cached Response if preValidateResponse and validatePostResponse succeded", async () => {
    const expectedAuthnRequestID = "123456";
    const mockPreValidate = jest
      .fn()
      .mockImplementation((_, __, ___, ____, callback) => {
        callback(null, true, expectedAuthnRequestID);
      });
    mockDel.mockImplementation((_) => Promise.resolve(1));
    const customSamlClient = new CustomSamlClient(
      { validateInResponseTo: true },
      redisCacheProvider,
      undefined,
      authReqTampener,
      mockPreValidate
    );
    mockGet.mockImplementation(async (_) =>
      JSON.stringify(expectedRequestData)
    );

    expect(customSamlClient).toBeTruthy();
    customSamlClient.validatePostResponse({ SAMLResponse: "" }, mockedCallback);
    expect(mockPreValidate).toBeCalledWith(
      { validateInResponseTo: true },
      { SAMLResponse: "" },
      redisCacheProvider,
      undefined,
      expect.any(Function)
    );
    // Before checking the execution of the callback we must await that the TaskEither execution is completed.
    await new Promise((resolve) => {
      setTimeout(() => {
        expect(mockGet).toBeCalledWith(`SAML-EXT-${expectedAuthnRequestID}`);
        expect(mockDel).toBeCalledWith(`SAML-EXT-${expectedAuthnRequestID}`);
        expect(mockedCallback).toBeCalledWith(
          null,
          { extraLoginRequestParams: {} },
          false
        );
        resolve(undefined);
      }, 100);
    });
  });

  it("should return extra login parameters stored in cache if preValidateResponse and validatePostResponse succeded", async () => {
    const expectedAuthnRequestID = "123456";
    const mockPreValidate = jest
      .fn()
      .mockImplementation((_, __, ___, ____, callback) => {
        callback(null, true, expectedAuthnRequestID);
      });
    mockDel.mockImplementation((_) => Promise.resolve(1));
    const customSamlClient = new CustomSamlClient(
      { validateInResponseTo: true },
      redisCacheProvider,
      undefined,
      authReqTampener,
      mockPreValidate
    );
    mockGet.mockImplementation(async (_) =>
      JSON.stringify({ ...expectedRequestData, ...expectedExtraParams })
    );

    expect(customSamlClient).toBeTruthy();
    customSamlClient.validatePostResponse({ SAMLResponse: "" }, mockedCallback);
    expect(mockPreValidate).toBeCalledWith(
      { validateInResponseTo: true },
      { SAMLResponse: "" },
      redisCacheProvider,
      undefined,
      expect.any(Function)
    );
    // Before checking the execution of the callback we must await that the TaskEither execution is completed.
    await new Promise((resolve) => {
      setTimeout(() => {
        expect(mockGet).toBeCalledWith(`SAML-EXT-${expectedAuthnRequestID}`);
        expect(mockDel).toBeCalledWith(`SAML-EXT-${expectedAuthnRequestID}`);
        expect(mockedCallback).toBeCalledWith(
          null,
          { extraLoginRequestParams: { ...expectedExtraParams } },
          false
        );
        resolve(undefined);
      }, 100);
    });
  });

  it("should validatePostResponse return an error if an error occurs deleting the SAML Request", async () => {
    const expectedAuthnRequestID = "123456";
    const expectedDelError = new Error("ErrorDel");
    const mockPreValidate = jest
      .fn()
      .mockImplementation((_, __, ___, ____, callback) => {
        callback(null, true, expectedAuthnRequestID);
      });
    mockDel.mockImplementation((_) => Promise.reject(expectedDelError));
    mockGet.mockImplementation(async (_) =>
      JSON.stringify(expectedRequestData)
    );

    const customSamlClient = new CustomSamlClient(
      { validateInResponseTo: true },
      redisCacheProvider,
      undefined,
      authReqTampener,
      mockPreValidate
    );
    expect(customSamlClient).toBeTruthy();
    customSamlClient.validatePostResponse({ SAMLResponse: "" }, mockedCallback);
    expect(mockPreValidate).toBeCalledWith(
      { validateInResponseTo: true },
      { SAMLResponse: "" },
      redisCacheProvider,
      undefined,
      expect.any(Function)
    );
    // Before checking the execution of the callback we must await that the TaskEither execution is completed.
    await new Promise((resolve) => {
      setTimeout(() => {
        expect(mockGet).toBeCalledWith(`SAML-EXT-${expectedAuthnRequestID}`);
        expect(mockDel).toBeCalledWith(`SAML-EXT-${expectedAuthnRequestID}`);
        expect(mockedCallback).toBeCalledWith(
          new Error(
            `SAML#ExtendedRedisCacheProvider: remove() error ${expectedDelError}`
          )
        );
        resolve(undefined);
      }, 100);
    });
  });
});

describe("CustomSamlClient#generateAuthorizeRequest", () => {
  const mockCallback = jest.fn();
  afterEach(() => {
    jest.resetAllMocks();
  });

  const samlConfigMock = {
    issuer: "ISSUER",
  } as any;

  const builder = new Builder({
    xmldec: { encoding: undefined, version: "1.0" },
  });

  it("should generateAuthorizeRequest call super generateAuthorizeRequest if tamperAuthorizeRequest is not provided", () => {
    const req = mockReq();
    const expectedXML = "<xml></xml>";
    mockWrapCallback.mockImplementation((callback) => {
      callback(null, expectedXML);
    });
    const customSamlClient = new CustomSamlClient(
      { validateInResponseTo: true },
      redisCacheProvider,
      undefined
    );
    customSamlClient.generateAuthorizeRequest(req, false, true, mockCallback);
    expect(mockCallback).toBeCalledWith(null, expectedXML);
  });

  it("should generateAuthorizeRequest save the SAML Request if tamperAuthorizeRequest is not provided", async () => {
    const mockAuthReqTampener = jest.fn().mockImplementation((xml) => {
      return fromEither(right(xml));
    });
    mockWrapCallback.mockImplementation((callback) => {
      callback(null, SAMLRequest);
    });
    const req = mockReq();
    mockSetEx.mockImplementation((_, __, ___) => Promise.resolve("OK"));
    const customSamlClient = new CustomSamlClient(
      {
        entryPoint: "https://localhost:3000/acs",
        idpIssuer: "https://localhost:8080",
        issuer: "https://localhost:3000",
        validateInResponseTo: true,
      },
      redisCacheProvider,
      undefined,
      mockAuthReqTampener
    );
    customSamlClient.generateAuthorizeRequest(req, false, true, mockCallback);
    expect(mockAuthReqTampener).toBeCalledWith(SAMLRequest, undefined);
    // Before checking the execution of the callback we must await that the TaskEither execution is completed.
    await new Promise((resolve) => {
      setTimeout(() => {
        expect(mockSetEx).toBeCalled();
        expect(mockCallback).toBeCalledWith(null, SAMLRequest);
        resolve(undefined);
      }, 100);
    });
  });

  it("should call tamperAuthorizeRequest with lollipop params if client send lollipop headers", async () => {
    const mockAuthReqTampener = jest.fn().mockImplementation((_) => {
      return fromEither(right(SAMLRequest));
    });
    mockWrapCallback.mockImplementation((callback) => {
      callback(null, SAMLRequest);
    });
    mockSetEx.mockImplementation((_, __, ___) => Promise.resolve("OK"));
    const customSamlClient = new CustomSamlClient(
      {
        entryPoint: "https://localhost:3000/acs",
        idpIssuer: "https://localhost:8080",
        issuer: "https://localhost:3000",
        validateInResponseTo: true,
      },
      redisCacheProvider,
      undefined,
      mockAuthReqTampener
    );

    const request = mockReq();
    request.headers[LOLLIPOP_PUB_KEY_HEADER_NAME] = jose.base64url.encode(
      JSON.stringify(aJwkPubKey)
    );
    customSamlClient.generateAuthorizeRequest(
      request,
      false,
      true,
      mockCallback
    );
    expect(mockAuthReqTampener).toBeCalledWith(SAMLRequest, {
      pubKey: aJwkPubKey,
    });
    // Before checking the execution of the callback we must await that the TaskEither execution is completed.
    await new Promise((resolve) => {
      setTimeout(() => {
        expect(mockSetEx).toBeCalled();
        expect(mockCallback).toBeCalledWith(null, SAMLRequest);
        resolve(undefined);
      }, 100);
    });
  });

  it("should not change JWK properties order while generating authorizeRequest if client send lollipop headers", async () => {
    const authReqTamperer = getAuthorizeRequestTamperer(
      builder,
      samlConfigMock
    );
    const jwkThumbprint = await jose.calculateJwkThumbprint(aJwkPubKey);
    const lollipopSamlRequest = samlRequestWithID(
      `${DEFAULT_LOLLIPOP_HASH_ALGORITHM}-${jwkThumbprint}`
    );
    mockWrapCallback.mockImplementation((callback) => {
      callback(null, samlRequest);
    });
    mockSetEx.mockImplementation((_, __, ___) => Promise.resolve("OK"));
    const customSamlClient = new CustomSamlClient(
      {
        entryPoint: "https://localhost:3000/acs",
        idpIssuer: "https://localhost:8080",
        issuer: "https://localhost:3000",
        validateInResponseTo: true,
      },
      redisCacheProvider,
      undefined,
      authReqTamperer
    );

    const request = mockReq();
    request.headers[LOLLIPOP_PUB_KEY_HEADER_NAME] = jose.base64url.encode(
      JSON.stringify(aJwkPubKey)
    );
    customSamlClient.generateAuthorizeRequest(
      request,
      false,
      true,
      mockCallback
    );

    const expectedSamlRequest = await pipe(
      authReqTamperer(lollipopSamlRequest, {
        pubKey: aJwkPubKey,
      }),
      TE.mapLeft(() => fail("Cannot tamper saml request")),
      TE.toUnion
    )();

    const expectedSamlRequestXML = await parseStringPromise(
      expectedSamlRequest
    );

    // Before checking the execution of the callback we must await that the TaskEither execution is completed.
    await new Promise((resolve) => {
      setTimeout(() => {
        expect(mockSetEx).toBeCalled();
        expect(mockCallback).toBeCalledWith(null, expectedSamlRequest);
        expect(`${DEFAULT_LOLLIPOP_HASH_ALGORITHM}-${jwkThumbprint}`).toEqual(
          expectedSamlRequestXML["samlp:AuthnRequest"].$.ID
        );
        resolve(undefined);
      }, 100);
    });
  });

  it("should generateAuthorizeRequest save the SAML Request and extra login parameters, if requestMapper is provided", async () => {
    const mockAuthReqTampener = jest.fn().mockImplementation((xml) => {
      return fromEither(right(xml));
    });

    const mockrequestMapper = jest
      .fn()
      .mockImplementation((_req) => E.of(expectedExtraParams));

    mockWrapCallback.mockImplementation((callback) => {
      callback(null, SAMLRequest);
    });
    const req = mockReq();
    mockSetEx.mockImplementation((_, __, ___) => Promise.resolve("OK"));
    const customSamlClient = new CustomSamlClient(
      {
        entryPoint: "https://localhost:3000/acs",
        idpIssuer: "https://localhost:8080",
        issuer: "https://localhost:3000",
        validateInResponseTo: true,
      },
      redisCacheProvider,
      mockrequestMapper,
      mockAuthReqTampener
    );
    customSamlClient.generateAuthorizeRequest(req, false, true, mockCallback);
    expect(mockAuthReqTampener).toBeCalledWith(SAMLRequest, undefined);

    // Before checking the execution of the callback we must await that the TaskEither execution is completed.
    await new Promise((resolve) => {
      setTimeout(() => {
        expect(mockSetEx).toHaveBeenCalledWith(
          `SAML-EXT-${expectedRequestID}`,
          expect.any(Number),
          expect.stringContaining("aNewParam")
        );
        expect(mockrequestMapper).toHaveBeenCalled();
        expect(mockCallback).toBeCalledWith(null, SAMLRequest);
        resolve(undefined);
      }, 100);
    });
  });

  it("should generateAuthorizeRequest save the SAML Request and no extra login parameters, if requestMapper returns a validation Error", async () => {
    const mockAuthReqTampener = jest.fn().mockImplementation((xml) => {
      return fromEither(right(xml));
    });

    const mockrequestMapper = jest
      .fn()
      .mockImplementation((_req) => E.left({}));

    mockWrapCallback.mockImplementation((callback) => {
      callback(null, SAMLRequest);
    });
    const req = mockReq();
    mockSetEx.mockImplementation((_, __, ___) => Promise.resolve("OK"));
    const customSamlClient = new CustomSamlClient(
      {
        entryPoint: "https://localhost:3000/acs",
        idpIssuer: "https://localhost:8080",
        issuer: "https://localhost:3000",
        validateInResponseTo: true,
      },
      redisCacheProvider,
      mockrequestMapper,
      mockAuthReqTampener
    );
    customSamlClient.generateAuthorizeRequest(req, false, true, mockCallback);
    expect(mockAuthReqTampener).toBeCalledWith(SAMLRequest, undefined);

    // Before checking the execution of the callback we must await that the TaskEither execution is completed.
    await new Promise((resolve) => {
      setTimeout(() => {
        expect(mockSetEx).toHaveBeenCalled();
        expect(mockrequestMapper).toHaveBeenCalled();
        expect(mockCallback).toBeCalledWith(null, SAMLRequest);
        resolve(undefined);
      }, 100);
    });
  });

  it("should generateAuthorizeRequest return an error if tamperAuthorizeRequest fail", async () => {
    const expectedTamperError = new Error("tamperAuthorizeRequest Error");
    const mockAuthReqTampener = jest.fn().mockImplementation((_) => {
      return fromEither(left(expectedTamperError));
    });
    mockWrapCallback.mockImplementation((callback) => {
      callback(null, SAMLRequest);
    });
    const req = mockReq();
    mockSetEx.mockImplementation((_, __, ___) => Promise.resolve("OK"));
    const customSamlClient = new CustomSamlClient(
      {
        entryPoint: "https://localhost:3000/acs",
        idpIssuer: "https://localhost:8080",
        issuer: "https://localhost:3000",
        validateInResponseTo: true,
      },
      redisCacheProvider,
      undefined,
      mockAuthReqTampener
    );
    customSamlClient.generateAuthorizeRequest(req, false, true, mockCallback);
    expect(mockAuthReqTampener).toBeCalledWith(SAMLRequest, undefined);
    // Before checking the execution of the callback we must await that the TaskEither execution is completed.
    await new Promise((resolve) => {
      setTimeout(() => {
        expect(mockSetEx).not.toBeCalled();
        expect(mockCallback).toBeCalledWith(expectedTamperError);
        resolve(undefined);
      }, 100);
    });
  });
});
