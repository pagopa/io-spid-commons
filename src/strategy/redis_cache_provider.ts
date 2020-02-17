import { fromOption, parseJSON, toError } from "fp-ts/lib/Either";
import { fromEither, TaskEither, taskify } from "fp-ts/lib/TaskEither";
import * as t from "io-ts";
import { UTCISODateFromString } from "italia-ts-commons/lib/dates";
import { readableReport } from "italia-ts-commons/lib/reporters";
import { CacheItem, CacheProvider } from "passport-saml";
import * as redis from "redis";
import { getIDFromRequest } from "../utils/saml";

const CacheItem = t.interface({
  createdAt: t.any,
  value: t.any
});

export type SAMLRequestCacheItem = t.TypeOf<typeof SAMLRequestCacheItem>;
const SAMLRequestCacheItem = t.interface({
  RequestXML: t.string,
  createdAt: UTCISODateFromString
});

export interface IExtendedCacheProvider {
  save: (RequestXML: string) => TaskEither<Error, SAMLRequestCacheItem>;
  get: (AuthnRequestID: string) => TaskEither<Error, SAMLRequestCacheItem>;
  remove: (AuthnRequestID: string) => TaskEither<Error, string>;
}

// those methods must never fail since there's
// practically no error handling in passport-saml
// (a very bad lot of spaghetti code)
export const getRedisCacheProvider = (
  redisClient: redis.RedisClient,
  // 1 hour by default
  keyExpirationPeriodSeconds: number = 3600,
  keyPrefix: string = "SAML-"
): CacheProvider => {
  return {
    // saves the key with the optional value
    // invokes the callback with the value saved
    save(key, value, callback): void {
      if (!key) {
        // should never happen
        callback(
          new Error(`SAML#RedisCacheProvider: cannot save an empty key`),
          (null as unknown) as CacheItem
        );
        return;
      }
      const v = {
        createdAt: new Date(),
        value
      };
      redisClient.set(
        `${keyPrefix}${key}`,
        JSON.stringify(v),
        "EX",
        keyExpirationPeriodSeconds,
        err => {
          if (err) {
            callback(
              new Error(`SAML#RedisCacheProvider: set() error ${err}`),
              (null as unknown) as CacheItem
            );
            return;
          }
          // returned valued is ignored by passport-saml
          callback(null, v);
        }
      );
    },
    // invokes 'callback' and passes the value if found, null otherwise
    get(key, callback): void {
      redisClient.get(`${keyPrefix}${key}`, (err, value) => {
        if (err) {
          callback(
            new Error(`SAML#RedisCacheProvider: get() error ${err}`),
            null
          );
          return;
        }
        parseJSON(value, toError)
          .chain(_ =>
            CacheItem.decode(_).mapLeft(
              __ =>
                new Error(
                  `SAML#RedisCacheProvider: get() error ${readableReport(__)}`
                )
            )
          )
          .fold(
            error => callback(error, null),
            v => callback(null, v.value)
          );
      });
    },
    // removes the key from the cache, invokes `callback` with the
    // key removed, null if no key is removed
    remove(key, callback): void {
      redisClient.del(`${keyPrefix}${key}`, err => {
        if (err) {
          callback(
            new Error(`SAML#RedisCacheProvider: remove() error ${err}`),
            (null as unknown) as string
          );
          return;
        }
        // returned valued is ignored by passport-saml
        callback(null, key);
      });
    }
  };
};

export const getExtendedRedisCacheProvider = (
  redisClient: redis.RedisClient,
  // 1 hour by default
  keyExpirationPeriodSeconds: number = 3600,
  keyPrefix: string = "SAML-EXT-"
): IExtendedCacheProvider => {
  return {
    save(RequestXML: string): TaskEither<Error, SAMLRequestCacheItem> {
      return fromEither(
        fromOption(
          new Error(`SAML#ExtendedRedisCacheProvider: missing AuthnRequest ID`)
        )(getIDFromRequest(RequestXML))
      ).chain(AuthnRequestID => {
        const v: SAMLRequestCacheItem = {
          RequestXML,
          createdAt: new Date()
        };
        return taskify(
          (
            key: string,
            data: string,
            flag: "EX",
            expiration: number,
            callback: (err: Error | null, value: unknown) => void
          ) => redisClient.set(key, data, flag, expiration, callback)
        )(
          `${keyPrefix}${AuthnRequestID}`,
          JSON.stringify(v),
          "EX",
          keyExpirationPeriodSeconds
        )
          .mapLeft(
            err =>
              new Error(`SAML#ExtendedRedisCacheProvider: set() error ${err}`)
          )
          .map(() => v);
      });
    },
    get(AuthnRequestID: string): TaskEither<Error, SAMLRequestCacheItem> {
      return taskify(redisClient.get)(`${keyPrefix}${AuthnRequestID}`)
        .mapLeft(
          err =>
            new Error(`SAML#ExtendedRedisCacheProvider: get() error ${err}`)
        )
        .chain(value =>
          fromEither(
            parseJSON(value, toError).chain(_ =>
              SAMLRequestCacheItem.decode(_).mapLeft(
                __ =>
                  new Error(
                    `SAML#ExtendedRedisCacheProvider: get() error ${readableReport(
                      __
                    )}`
                  )
              )
            )
          )
        );
    },
    remove(AuthnRequestID): TaskEither<Error, string> {
      return taskify(
        (key: string, callback: (err: Error | null, value: unknown) => void) =>
          redisClient.del(key, callback)
      )(`${keyPrefix}${AuthnRequestID}`)
        .mapLeft(
          err =>
            new Error(`SAML#ExtendedRedisCacheProvider: remove() error ${err}`)
        )
        .map(() => AuthnRequestID);
    }
  };
};
