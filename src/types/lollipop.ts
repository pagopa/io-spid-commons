import { JwkPublicKey } from "@pagopa/ts-commons/lib/jwk";
import * as t from "io-ts";

export const LollipopHashAlgorithm = t.union([
  t.literal("sha256"),
  t.literal("sha384"),
  t.literal("sha512"),
]);
export type LollipopHashAlgorithm = t.TypeOf<typeof LollipopHashAlgorithm>;

export const DEFAULT_LOLLIPOP_HASH_ALGORITHM: LollipopHashAlgorithm = "sha256";
export interface ILollipopParams {
  readonly pubKey: JwkPublicKey;
  readonly hashAlgorithm?: LollipopHashAlgorithm;
}

export const LOLLIPOP_PUB_KEY_HEADER_NAME = "x-pagopa-lollipop-pub-key";
export const LOLLIPOP_PUB_KEY_HASHING_ALGO_HEADER_NAME =
  "x-pagopa-lollipop-pub-key-hash-algo";
