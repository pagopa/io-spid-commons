import { JwkPublicKey } from "@pagopa/ts-commons/lib/jwk";
import { NonEmptyString, Semver } from "@pagopa/ts-commons/lib/strings";
import { flow, pipe } from "fp-ts/lib/function";
import * as E from "fp-ts/lib/Either";
import * as t from "io-ts";
import { errorsToReadableMessages } from "@pagopa/ts-commons/lib/reporters";
import * as EQ from "fp-ts/lib/Eq";
import * as semver from "semver";

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

export const UserAgentSemver = t.type({
  clientName: NonEmptyString,
  clientVersion: Semver
});

export type UserAgentSemver = t.TypeOf<typeof UserAgentSemver>;

export const UserAgentSemverValid: EQ.Eq<UserAgentSemver> = {
  equals: (first, second) =>
    first.clientName === second.clientName &&
    semver.satisfies(second.clientVersion, `<=${first.clientVersion}`)
};

export const SemverFromFromUserAgentString = new t.Type<
  UserAgentSemver,
  string
>(
  "SemverFromFromUserAgent",
  (u): u is UserAgentSemver =>
    pipe(
      u,
      t.string.decode,
      E.fold(
        () => false,
        s =>
          pipe(
            s.substring(s.indexOf(`/`) + 1),
            ver => ({
              clientName: s.substring(0, s.indexOf(`/`)),
              clientVersion: ver
                .split(".")
                .slice(0, 3)
                .join(".")
            }),
            UserAgentSemver.is
          )
      )
    ),
  (s, ctx) =>
    pipe(
      s,
      t.string.decode,
      E.mapLeft(errs => Error(errorsToReadableMessages(errs).join("|"))),
      E.map(str =>
        pipe(str.substring(str.indexOf(`/`) + 1), ver => ({
          clientName: str.substring(0, str.indexOf(`/`)),
          clientVersion: ver
            .split(".")
            .slice(0, 3)
            .join(".")
        }))
      ),
      E.chainW(
        flow(
          UserAgentSemver.decode,
          E.mapLeft(errs => Error(errorsToReadableMessages(errs).join("|")))
        )
      ),
      E.fold(e => t.failure(s, ctx, e.message), t.success)
    ),
  u => `${u.clientName}/${u.clientVersion}`
);

export type SemverFromFromUserAgentString = t.TypeOf<
  typeof SemverFromFromUserAgentString
>;
