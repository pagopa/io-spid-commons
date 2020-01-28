import { parseJSON, toError } from "fp-ts/lib/Either";
import { CacheItem, CacheProvider } from "passport-saml";
import * as redis from "redis";

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
        parseJSON(value, toError).fold(
          _ => callback(_, null),
          _ => callback(null, _)
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
