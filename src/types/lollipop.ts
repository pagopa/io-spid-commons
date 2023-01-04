import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import { flow, pipe } from "fp-ts/lib/function";
import * as E from "fp-ts/lib/Either";
import * as J from "fp-ts/lib/Json";
import * as t from "io-ts";
import * as jose from "jose";
import { errorsToReadableMessages } from "@pagopa/ts-commons/lib/reporters";

export const LollipopHashAlgorithm = t.union([
  t.literal("sha256"),
  t.literal("sha384"),
  t.literal("sha512")
]);
export type LollipopHashAlgorithm = t.TypeOf<typeof LollipopHashAlgorithm>;

export const DEFAULT_LOLLIPOP_HASH_ALGORITHM: LollipopHashAlgorithm = "sha256";
export interface ILollipopParams {
  // eslint-disable-next-line functional/prefer-readonly-type
  readonly userAgent?: string | string[];
  readonly pubKey: JwkPublicKey;
  readonly hashAlgorithm?: LollipopHashAlgorithm;
}

export const LOLLIPOP_PUB_KEY_HEADER_NAME = "x-pagopa-lollipop-pub-key";
export const LOLLIPOP_PUB_KEY_HASHING_ALGO_HEADER_NAME =
  "x-pagopa-lollipop-pub-key-hash-algo";

/**
 * -----------------------------------------------------------------
 * Consider to move the following types to `ts-commons` to share it
 * across clients and server implementations.
 * -----------------------------------------------------------------
 */

/**
 * This is the JWK JSON type for the EC keys.
 */
export const ECKey = t.type({
  crv: t.string,
  kty: t.literal("EC"),
  x: t.string,
  y: t.string
});

export type ECKey = t.TypeOf<typeof ECKey>;

/**
 * This is the JWK JSON type for the RSA keys.
 */
export const RSAKey = t.type({
  alg: t.string,
  e: t.string,
  kty: t.literal("RSA"),
  n: t.string
});

export type RSAKey = t.TypeOf<typeof RSAKey>;

/**
 * The Public Key JWK type. It could be either an ECKey or an RSAKey.
 */
export const JwkPublicKey = t.union([RSAKey, ECKey], "JwkPublicKey");
export type JwkPublicKey = t.TypeOf<typeof JwkPublicKey>;

export const parseJwkOrError = (token: unknown): E.Either<Error, J.Json> =>
  pipe(
    token,
    NonEmptyString.decode,
    E.mapLeft(E.toError),
    E.chain(tokenStr =>
      E.tryCatch(
        () =>
          pipe(
            Buffer.from(jose.base64url.decode(tokenStr)),
            E.fromPredicate(
              b => b.length > 0,
              () => {
                throw new Error("Unexpected JWK empty buffer");
              }
            ),
            E.map(b => b.toString()),
            E.toUnion
          ),
        _ => Error("Cannot decode JWK Base64")
      )
    ),
    E.chain(
      flow(
        J.parse,
        E.mapLeft(_ => Error("Cannot parse JWK to JSON format"))
      )
    )
  );

export const JwkPublicKeyFromToken = new t.Type<JwkPublicKey, string>(
  "JwkPublicKeyFromToken",
  (s): s is JwkPublicKey =>
    pipe(s, parseJwkOrError, E.toUnion, JwkPublicKey.is),
  (s, ctx) =>
    pipe(
      s,
      parseJwkOrError,
      E.chainW(
        flow(
          JwkPublicKey.decode,
          E.mapLeft(errs => Error(errorsToReadableMessages(errs).join("|")))
        )
      ),
      E.fold(e => t.failure(s, ctx, e.message), t.success)
    ),
  flow(
    J.stringify,
    E.map(jose.base64url.encode),
    E.getOrElseW(_ => {
      throw new Error("Cannot stringify a malformed json");
    })
  )
);
export type JwkPublicKeyFromToken = t.TypeOf<typeof JwkPublicKeyFromToken>;
