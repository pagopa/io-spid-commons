import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";

export interface ILollipopParams {
  // eslint-disable-next-line functional/prefer-readonly-type
  readonly userAgent?: string | string[];
  readonly pubKey: NonEmptyString;
}

export const LOLLIPOP_PUB_KEY_HEADER_NAME = "x-pagopa-lollipop-pub-key";
