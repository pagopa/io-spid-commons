import { UTCISODateFromString } from "@pagopa/ts-commons/lib/dates";
import { readableReport } from "@pagopa/ts-commons/lib/reporters";
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
  idpIssuer: t.string,
});

export interface IExtendedCacheProvider<T extends Record<string, unknown>> {
  readonly save: (
    RequestXML: string,
    samlConfig: SamlConfig,
    extraLoginRequestParams: T | undefined
  ) => TaskEither<Error, SAMLRequestCacheItem | (SAMLRequestCacheItem & T)>;
  readonly get: (
    AuthnRequestID: string
  ) => TaskEither<Error, SAMLRequestCacheItem | (SAMLRequestCacheItem & T)>;
  readonly remove: (AuthnRequestID: string) => TaskEither<Error, string>;
}

// those methods must never fail since there's
// practically no error handling in passport-saml
// (a very bad lot of spaghetti code)
export const noopCacheProvider = (): CacheProvider => ({
  // invokes 'callback' and passes the value if found, null otherwise
  get: (_, callback): void => {
    callback(null, {});
  },

  // removes the key from the cache, invokes `callback` with the
  // key removed, null if no key is removed
  remove: (key, callback): void => {
    callback(null, key);
  },

  // saves the key with the optional value
  // invokes the callback with the value saved
  save: (_, value, callback): void => {
    const v = {
      createdAt: new Date(),
      value,
    };
    callback(null, v);
  },
});

export const getExtendedRedisCacheProvider = <
  T extends Record<string, unknown> = Record<string, never>
>(
  redisClient: redis.RedisClientType | redis.RedisClusterType,
  extraLoginRequestParamsCodec?: t.Type<T, T, unknown>,
  // 1 hour by default
  keyExpirationPeriodSeconds: Second = 3600 as Second,
  keyPrefix: string = "SAML-EXT-"
): IExtendedCacheProvider<T> => ({
  get: (
    AuthnRequestID: string
  ): TaskEither<Error, SAMLRequestCacheItem | (SAMLRequestCacheItem & T)> =>
    pipe(
      TE.tryCatch(
        () => redisClient.get(`${keyPrefix}${AuthnRequestID}`),
        E.toError
      ),
      TE.mapLeft(
        (err) =>
          new Error(`SAML#ExtendedRedisCacheProvider: get() error ${err}`)
      ),
      // redis callbacks consider empty value as null instead of undefined,
      // hence the need for the following wrapper to convert nulls to undefined
      TE.chain(
        TE.fromPredicate(
          (v): v is string => v !== null,
          () =>
            // If the value is missing a specific error is returned
            // This avoid to continue the execution with a Validation left from
            // SAMLRequestCacheItem decode.
            new Error("SAML#ExtendedRedisCacheProvider: get() value not found")
        )
      ),
      TE.chain((value) =>
        TE.fromEither(
          pipe(
            E.parseJSON(value, E.toError),
            E.chain((_) =>
              pipe(
                SAMLRequestCacheItem.decode(_),
                E.map((samlRequestCacheItem) => ({
                  ...samlRequestCacheItem,
                  ...pipe(
                    extraLoginRequestParamsCodec,
                    E.fromNullable(undefined),
                    E.chainW((codec) => codec.decode(_)),
                    E.getOrElseW(() => ({}))
                  ),
                })),
                E.mapLeft(
                  (__) =>
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
    ),
  remove: (AuthnRequestID): TaskEither<Error, string> =>
    pipe(
      TE.tryCatch(
        () => redisClient.del(`${keyPrefix}${AuthnRequestID}`),
        E.toError
      ),
      TE.mapLeft(
        (err) =>
          new Error(`SAML#ExtendedRedisCacheProvider: remove() error ${err}`)
      ),
      TE.map(() => AuthnRequestID)
    ),
  save: (
    RequestXML: string,
    samlConfig: SamlConfig,
    extraLoginRequestParams: T | undefined
  ): TaskEither<Error, SAMLRequestCacheItem | (SAMLRequestCacheItem & T)> =>
    pipe(
      TE.fromEither(
        E.fromOption(
          () =>
            new Error(
              `SAML#ExtendedRedisCacheProvider: missing AuthnRequest ID`
            )
        )(getIDFromRequest(RequestXML))
      ),
      TE.chain((AuthnRequestID) =>
        pipe(
          TE.fromEither(
            E.fromOption(
              () => new Error("Missing idpIssuer inside configuration")
            )(O.fromNullable(samlConfig.idpIssuer))
          ),
          TE.map((idpIssuer) => ({ AuthnRequestID, idpIssuer }))
        )
      ),
      TE.chain((_) => {
        const v: SAMLRequestCacheItem | (SAMLRequestCacheItem & T) = {
          ...extraLoginRequestParams,
          RequestXML,
          createdAt: new Date(),
          idpIssuer: _.idpIssuer,
        };
        return pipe(
          TE.tryCatch(
            () =>
              redisClient.setEx(
                `${keyPrefix}${_.AuthnRequestID}`,
                keyExpirationPeriodSeconds,
                JSON.stringify(v)
              ),
            E.toError
          ),
          TE.mapLeft(
            (err) =>
              new Error(`SAML#ExtendedRedisCacheProvider: set() error ${err}`)
          ),
          TE.map(() => v)
        );
      })
    ),
});
