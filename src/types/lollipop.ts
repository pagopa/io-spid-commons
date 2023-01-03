import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";

export enum LollipopHashAlgorithm {
  SHA256 = "sha256",
  SHA512 = "sha512",
  SHA384 = "sha384",
  RIPEMD160 = "ripemd160"
}

export const DEFAULT_LOLLIPOP_HASH_ALGORITHM = LollipopHashAlgorithm.SHA256;
export interface ILollipopParams {
  // eslint-disable-next-line functional/prefer-readonly-type
  readonly userAgent?: string | string[];
  readonly pubKey: NonEmptyString;
  readonly hashAlgorithm?: LollipopHashAlgorithm;
}

export const LOLLIPOP_PUB_KEY_HEADER_NAME = "x-pagopa-lollipop-pub-key";
