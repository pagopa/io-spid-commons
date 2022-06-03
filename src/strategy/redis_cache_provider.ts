// eslint-disable-next-line import/no-internal-modules
import { UTCISODateFromString } from "@pagopa/ts-commons/lib/dates";
// eslint-disable-next-line import/no-internal-modules
import { readableReport } from "@pagopa/ts-commons/lib/reporters";
// eslint-disable-next-line import/no-internal-modules
import { Second } from "@pagopa/ts-commons/lib/units";
import * as E from "fp-ts/lib/Either";
import { pipe } from "fp-ts/lib/function";
import * as O from "fp-ts/lib/Option";
import * as TE from "fp-ts/lib/TaskEither";
import { TaskEither } from "fp-ts/lib/TaskEither";
import * as t from "io-ts";
import { CacheProvider, SamlConfig } from "passport-saml";
import * as redis from "redis";
import { getIDFromRequest } from "../utils/saml";

export type SAMLRequestCacheItem = t.TypeOf<typeof SAMLRequestCacheItem>;
const SAMLRequestCacheItem = t.interface({
  RequestXML: t.string,
  createdAt: UTCISODateFromString,
  idpIssuer: t.string
});

export interface IExtendedCacheProvider {
  readonly save: (
    RequestXML: string,
    samlConfig: SamlConfig
  ) => TaskEither<Error, SAMLRequestCacheItem>;
  readonly get: (
    AuthnRequestID: string
  ) => TaskEither<Error, SAMLRequestCacheItem>;
  readonly remove: (AuthnRequestID: string) => TaskEither<Error, string>;
}

// those methods must never fail since there's
// practically no error handling in passport-saml
// (a very bad lot of spaghetti code)
export const noopCacheProvider = (): CacheProvider => ({
  // saves the key with the optional value
  // invokes the callback with the value saved
  // eslint-disable-next-line prefer-arrow/prefer-arrow-functions
  save(_, value, callback): void {
    const v = {
      createdAt: new Date(),
      value
    };
    callback(null, v);
  },
  // invokes 'callback' and passes the value if found, null otherwise
  // eslint-disable-next-line sort-keys, prefer-arrow/prefer-arrow-functions
  get(_, callback): void {
    callback(null, {});
  },
  // removes the key from the cache, invokes `callback` with the
  // key removed, null if no key is removed
  // eslint-disable-next-line prefer-arrow/prefer-arrow-functions
  remove(key, callback): void {
    callback(null, key);
  }
});

export const getExtendedRedisCacheProvider = (
  redisClient: redis.RedisClient,
  // 1 hour by default
  keyExpirationPeriodSeconds: Second = 3600 as Second,
  keyPrefix: string = "SAML-EXT-"
): IExtendedCacheProvider => ({
  // eslint-disable-next-line prefer-arrow/prefer-arrow-functions
  save(
    RequestXML: string,
    samlConfig: SamlConfig
  ): TaskEither<Error, SAMLRequestCacheItem> {
    return pipe(
      TE.fromEither(
        E.fromOption(
          () =>
            new Error(
              `SAML#ExtendedRedisCacheProvider: missing AuthnRequest ID`
            )
        )(getIDFromRequest(RequestXML))
      ),
      TE.chain(AuthnRequestID =>
        pipe(
          TE.fromEither(
            E.fromOption(
              () => new Error("Missing idpIssuer inside configuration")
            )(O.fromNullable(samlConfig.idpIssuer))
          ),
          // eslint-disable-next-line sort-keys
          TE.map(idpIssuer => ({ idpIssuer, AuthnRequestID }))
        )
      ),
      TE.chain(_ => {
        const v: SAMLRequestCacheItem = {
          RequestXML,
          createdAt: new Date(),
          idpIssuer: _.idpIssuer
        };
        return pipe(
          TE.taskify(
            (
              key: string,
              data: string,
              flag: "EX",
              expiration: number,
              callback: (err: Error | null, value: unknown) => void
            ) => redisClient.set(key, data, flag, expiration, callback)
          )(
            `${keyPrefix}${_.AuthnRequestID}`,
            JSON.stringify(v),
            "EX",
            keyExpirationPeriodSeconds
          ),
          TE.mapLeft(
            err =>
              new Error(`SAML#ExtendedRedisCacheProvider: set() error ${err}`)
          ),
          TE.map(() => v)
        );
      })
    );
  },
  // eslint-disable-next-line sort-keys, prefer-arrow/prefer-arrow-functions
  get(AuthnRequestID: string): TaskEither<Error, SAMLRequestCacheItem> {
    return pipe(
      TE.taskify(
        (key: string, callback: (e: Error | null, value?: string) => void) => {
          redisClient.get(key, (e, v) =>
            // redis callbacks consider empty value as null instead of undefined,
            //  hence the need for the following wrapper to convert nulls to undefined
            callback(e, v === null ? undefined : v)
          );
        }
      )(`${keyPrefix}${AuthnRequestID}`),
      TE.mapLeft(
        err => new Error(`SAML#ExtendedRedisCacheProvider: get() error ${err}`)
      ),
      TE.chain(value =>
        TE.fromEither(
          pipe(
            E.parseJSON(value, E.toError),
            E.chain(_ =>
              pipe(
                SAMLRequestCacheItem.decode(_),
                E.mapLeft(
                  __ =>
                    new Error(
                      `SAML#ExtendedRedisCacheProvider: get() error ${readableReport(
                        __
                      )}`
                    )
                )
              )
            )
          )
        )
      )
    );
  },
  // eslint-disable-next-line prefer-arrow/prefer-arrow-functions
  remove(AuthnRequestID): TaskEither<Error, string> {
    return pipe(
      TE.taskify(
        (key: string, callback: (err: Error | null, value?: unknown) => void) =>
          redisClient.del(key, callback)
      )(`${keyPrefix}${AuthnRequestID}`),
      TE.mapLeft(
        err =>
          new Error(`SAML#ExtendedRedisCacheProvider: remove() error ${err}`)
      ),
      TE.map(() => AuthnRequestID)
    );
  }
});
