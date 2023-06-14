import { RedisClientType, RedisClusterType } from "@redis/client";
import { isLeft, isRight } from "fp-ts/lib/Either";
import { SamlConfig } from "passport-saml";
import {
  getExtendedRedisCacheProvider,
  noopCacheProvider,
  SAMLRequestCacheItem,
} from "../redis_cache_provider";
import {
  expectedExtraParams,
  expectedExtraParamsC,
} from "../../__mocks__/extraParams";

const mockSetEx = jest.fn();
const mockGet = jest.fn();
const mockDel = jest.fn();

const mockRedisClient: RedisClientType | RedisClusterType =
  {} as RedisClientType;
mockRedisClient.setEx = mockSetEx;
mockRedisClient.get = mockGet;
mockRedisClient.del = mockDel;

const keyExpirationPeriodSeconds = 3600;
const expectedRequestID = "_ab0c7302158bde147963";
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

describe("noopCacheProvider", () => {
  const mockCallback = jest.fn();
  const expectedKey = "SAML-XXX";
  const expectedValue = "Value";
  beforeEach(() => {
    jest.clearAllMocks();
  });
  it("should save method of noopCacheProvider do noting", () => {
    noopCacheProvider().save(expectedKey, expectedValue, mockCallback);
    expect(mockCallback).toBeCalledWith(null, {
      createdAt: expect.any(Date),
      value: expectedValue,
    });
  });
  it("should get method of noopCacheProvider do noting", () => {
    noopCacheProvider().get(expectedKey, mockCallback);
    expect(mockCallback).toBeCalledWith(null, {});
  });
  it("should remove method of noopCacheProvider do noting", () => {
    noopCacheProvider().remove(expectedKey, mockCallback);
    expect(mockCallback).toBeCalledWith(null, expectedKey);
  });
});

describe("getExtendedRedisCacheProvider#save", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });
  it("should return the saved SAML Request data", async () => {
    mockSetEx.mockImplementation((_, __, ___) => Promise.resolve("OK"));
    const redisCacheProvider = getExtendedRedisCacheProvider(
      mockRedisClient as any
    );
    const cacheSAMLResponse = await redisCacheProvider.save(
      SAMLRequest,
      samlConfig,
      undefined
    )();
    expect(mockSetEx.mock.calls[0][0]).toBe(`SAML-EXT-${expectedRequestID}`);
    expect(mockSetEx.mock.calls[0][1]).toBe(keyExpirationPeriodSeconds);
    expect(mockSetEx.mock.calls[0][2]).toEqual(expect.any(String));
    expect(isRight(cacheSAMLResponse)).toBeTruthy();
    if (isRight(cacheSAMLResponse)) {
      expect(cacheSAMLResponse.right).toEqual({
        RequestXML: SAMLRequest,
        createdAt: expect.any(Date),
        idpIssuer: samlConfig.idpIssuer,
      });
    }
  });

  it("should return the saved SAML Request data with extra login parameters, if defined", async () => {
    mockSetEx.mockImplementation((_, __, ___) => Promise.resolve("OK"));
    const redisCacheProvider = getExtendedRedisCacheProvider(
      mockRedisClient as any,
      expectedExtraParamsC
    );
    const cacheSAMLResponse = await redisCacheProvider.save(
      SAMLRequest,
      samlConfig,
      expectedExtraParams
    )();
    expect(mockSetEx.mock.calls[0][0]).toBe(`SAML-EXT-${expectedRequestID}`);
    expect(mockSetEx.mock.calls[0][1]).toBe(keyExpirationPeriodSeconds);
    expect(mockSetEx.mock.calls[0][2]).toEqual(expect.any(String));
    expect(mockSetEx.mock.calls[0][2]).toEqual(
      expect.stringContaining("aNewParam")
    );
    expect(mockSetEx.mock.calls[0][2]).toEqual(
      expect.stringContaining("anotherParam")
    );
    expect(isRight(cacheSAMLResponse)).toBeTruthy();
    if (isRight(cacheSAMLResponse)) {
      expect(cacheSAMLResponse.right).toEqual({
        RequestXML: SAMLRequest,
        createdAt: expect.any(Date),
        idpIssuer: samlConfig.idpIssuer,
        ...expectedExtraParams,
      });
    }
  });

  it("should return an error if save on radis fail", async () => {
    const expectedRedisError = new Error("saveError");
    mockSetEx.mockImplementation((_, __, ___) =>
      Promise.reject(expectedRedisError)
    );
    const redisCacheProvider = getExtendedRedisCacheProvider(
      mockRedisClient as any
    );
    const cacheSAMLResponse = await redisCacheProvider.save(
      SAMLRequest,
      samlConfig,
      undefined
    )();
    expect(mockSetEx.mock.calls[0][0]).toBe(`SAML-EXT-${expectedRequestID}`);
    expect(mockSetEx.mock.calls[0][1]).toBe(keyExpirationPeriodSeconds);
    expect(mockSetEx.mock.calls[0][2]).toEqual(expect.any(String));
    expect(isRight(cacheSAMLResponse)).toBeFalsy();
    if (isLeft(cacheSAMLResponse)) {
      expect(cacheSAMLResponse.left).toEqual(
        new Error(
          `SAML#ExtendedRedisCacheProvider: set() error ${expectedRedisError}`
        )
      );
    }
  });
  it("should return an error if idpIssuer is missing inside samlConfig", async () => {
    const redisCacheProvider = getExtendedRedisCacheProvider(
      mockRedisClient as any
    );
    const cacheSAMLResponse = await redisCacheProvider.save(
      SAMLRequest,
      {},
      undefined
    )();
    expect(isRight(cacheSAMLResponse)).toBeFalsy();
    if (isLeft(cacheSAMLResponse)) {
      expect(cacheSAMLResponse.left).toEqual(
        new Error("Missing idpIssuer inside configuration")
      );
    }
  });
  it("should return an error if Request ID is missing", async () => {
    const SAMLRequestWithoutID = SAMLRequest.replace(
      `ID="${expectedRequestID}"`,
      ""
    );
    const redisCacheProvider = getExtendedRedisCacheProvider(
      mockRedisClient as any
    );
    const cacheSAMLResponse = await redisCacheProvider.save(
      SAMLRequestWithoutID,
      samlConfig,
      undefined
    )();
    expect(isRight(cacheSAMLResponse)).toBeFalsy();
    if (isLeft(cacheSAMLResponse)) {
      expect(cacheSAMLResponse.left).toEqual(
        new Error(`SAML#ExtendedRedisCacheProvider: missing AuthnRequest ID`)
      );
    }
  });
});

describe("getExtendedRedisCacheProvider#get", () => {
  it("should return the saved SAML Request data if exists", async () => {
    const expectedRequestData: SAMLRequestCacheItem = {
      RequestXML: SAMLRequest,
      createdAt: new Date(),
      idpIssuer: samlConfig.idpIssuer as string,
    };
    mockGet.mockImplementation((_) =>
      Promise.resolve(JSON.stringify(expectedRequestData))
    );
    const redisCacheProvider = getExtendedRedisCacheProvider(
      mockRedisClient as any
    );
    const cacheSAMLResponse = await redisCacheProvider.get(expectedRequestID)();
    expect(mockGet.mock.calls[0][0]).toBe(`SAML-EXT-${expectedRequestID}`);
    expect(isRight(cacheSAMLResponse)).toBeTruthy();
    if (isRight(cacheSAMLResponse)) {
      expect(cacheSAMLResponse.right).toEqual(expectedRequestData);
    }
  });

  it("should return the saved SAML Request data with extra login params, if exists", async () => {
    const expectedRequestData: SAMLRequestCacheItem = {
      RequestXML: SAMLRequest,
      createdAt: new Date(),
      idpIssuer: samlConfig.idpIssuer as string,
    };
    mockGet.mockImplementation((_) =>
      Promise.resolve(
        JSON.stringify({ ...expectedRequestData, ...expectedExtraParams })
      )
    );
    const redisCacheProvider = getExtendedRedisCacheProvider(
      mockRedisClient as any,
      expectedExtraParamsC
    );
    const cacheSAMLResponse = await redisCacheProvider.get(expectedRequestID)();
    expect(mockGet.mock.calls[0][0]).toBe(`SAML-EXT-${expectedRequestID}`);
    expect(isRight(cacheSAMLResponse)).toBeTruthy();
    if (isRight(cacheSAMLResponse)) {
      expect(cacheSAMLResponse.right).toEqual(
        expect.objectContaining({
          ...expectedExtraParams,
        })
      );
    }
  });
  it("should return an error if the reading process on redis fail", async () => {
    const expectedRedisError = new Error("readError");
    mockGet.mockImplementation((_) => Promise.reject(expectedRedisError));
    const redisCacheProvider = getExtendedRedisCacheProvider(
      mockRedisClient as any
    );
    const cacheSAMLResponse = await redisCacheProvider.get(expectedRequestID)();
    expect(mockGet.mock.calls[0][0]).toBe(`SAML-EXT-${expectedRequestID}`);
    expect(isRight(cacheSAMLResponse)).toBeFalsy();
    if (isLeft(cacheSAMLResponse)) {
      expect(cacheSAMLResponse.left).toEqual(
        new Error(
          `SAML#ExtendedRedisCacheProvider: get() error ${expectedRedisError}`
        )
      );
    }
  });
  it("should return an error cached Request is not compliant", async () => {
    const invalidCachedRequestData = {
      RequestXML: SAMLRequest,
      createdAt: new Date(),
      idpIssuer: undefined,
    };
    mockGet.mockImplementation((_) =>
      Promise.resolve(JSON.stringify(invalidCachedRequestData))
    );
    const redisCacheProvider = getExtendedRedisCacheProvider(
      mockRedisClient as any
    );
    const cacheSAMLResponse = await redisCacheProvider.get(expectedRequestID)();
    expect(mockGet.mock.calls[0][0]).toBe(`SAML-EXT-${expectedRequestID}`);
    expect(isRight(cacheSAMLResponse)).toBeFalsy();
    if (isLeft(cacheSAMLResponse)) {
      expect(cacheSAMLResponse.left).toEqual(expect.any(Error));
    }
  });
  it("should return an error if the cached Request is missing", async () => {
    mockGet.mockImplementation((_) => Promise.resolve(null));
    const redisCacheProvider = getExtendedRedisCacheProvider(
      mockRedisClient as any
    );
    const cacheSAMLResponse = await redisCacheProvider.get(expectedRequestID)();
    expect(mockGet.mock.calls[0][0]).toBe(`SAML-EXT-${expectedRequestID}`);
    expect(isRight(cacheSAMLResponse)).toBeFalsy();
    if (isLeft(cacheSAMLResponse)) {
      expect(cacheSAMLResponse.left).toEqual(expect.any(Error));
    }
  });
});

describe("getExtendedRedisCacheProvider#remove", () => {
  it("should return the RequestID if the deletion process succeded", async () => {
    mockDel.mockImplementation((_) => Promise.resolve(1));
    const redisCacheProvider = getExtendedRedisCacheProvider(
      mockRedisClient as any
    );
    const maybeRequestId = await redisCacheProvider.remove(expectedRequestID)();
    expect(mockDel.mock.calls[0][0]).toBe(`SAML-EXT-${expectedRequestID}`);
    expect(isRight(maybeRequestId)).toBeTruthy();
    if (isRight(maybeRequestId)) {
      expect(maybeRequestId.right).toBe(expectedRequestID);
    }
  });

  it("should return an error if the cache's deletion fail", async () => {
    const expectedDelRedisError = new Error("delError");
    mockDel.mockImplementation((_) => Promise.reject(expectedDelRedisError));
    const redisCacheProvider = getExtendedRedisCacheProvider(
      mockRedisClient as any
    );
    const maybeRequestId = await redisCacheProvider.remove(expectedRequestID)();
    expect(mockDel.mock.calls[0][0]).toBe(`SAML-EXT-${expectedRequestID}`);
    expect(isRight(maybeRequestId)).toBeFalsy();
    if (isLeft(maybeRequestId)) {
      expect(maybeRequestId.left).toEqual(
        new Error(
          `SAML#ExtendedRedisCacheProvider: remove() error ${expectedDelRedisError}`
        )
      );
    }
  });
});
