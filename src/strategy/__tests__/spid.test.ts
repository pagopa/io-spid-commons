import { RedisClientType } from "@redis/client";
import * as express from "express";
import { Profile, VerifiedCallback } from "passport-saml";
import { getSamlOptions } from "../../utils/saml";
import * as redisCacheProvider from "../redis_cache_provider";
import { SpidStrategy } from "../spid";

const mockRedisClient = {} as RedisClientType;

describe("SamlStrategy prototype arguments check", () => {
  let OriginalPassportSaml: any;
  beforeAll(() => {
    OriginalPassportSaml = jest.requireActual("passport-saml").Strategy;
  });
  it("should SamlStrategy constructor has 2 parameters", () => {
    expect(OriginalPassportSaml.prototype.constructor).toHaveLength(2);
  });
  it("should SamlStrategy authenticate has 2 parameters", () => {
    expect(OriginalPassportSaml.prototype.authenticate).toHaveLength(2);
  });
});

describe("SamlStrategy#constructor", () => {
  beforeAll(() => {
    jest.restoreAllMocks();
  });
  it("should SamlStrategy constructor has 2 parameters", () => {
    const expectedNoopCacheProvider = {
      get: () => () => {
        return;
      },
      remove: () => () => {
        return;
      },
      save: () => {
        return;
      }
    };
    const mockNoopCacheProvider = jest
      .spyOn(redisCacheProvider, "noopCacheProvider")
      .mockImplementation(() => expectedNoopCacheProvider);
    const spidStrategy = new SpidStrategy(
      {},
      getSamlOptions,
      (_: express.Request, profile: Profile, done: VerifiedCallback) => {
        // at this point SAML authentication is successful
        // `done` is a passport callback that signals success
        done(null, profile);
      },
      mockRedisClient as any
    );

    expect(spidStrategy["options"]).toHaveProperty(
      "requestIdExpirationPeriodMs",
      900000
    );

    expect(spidStrategy["options"]).toHaveProperty(
      "cacheProvider",
      expectedNoopCacheProvider
    );
    expect(mockNoopCacheProvider).toBeCalledTimes(1);

    expect(spidStrategy["extendedRedisCacheProvider"]).toBeTruthy();
  });
});

describe("loadFromRemote", () => {
  it("should reject if the fetch of IdP metadata fails", async () => {
    expect(true).toBeTruthy();
  });

  it("should reject if the IdP metadata are fetched from a wrong path", async () => {
    expect(true).toBeTruthy();
  });

  it("should reject an error if the fetch of IdP metadata returns no useful data", async () => {
    expect(true).toBeTruthy();
  });

  it("should resolve with the fetched IdP options", async () => {
    expect(true).toBeTruthy();
  });
});
