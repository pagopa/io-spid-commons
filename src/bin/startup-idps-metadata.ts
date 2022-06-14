#!/usr/bin/env node

import * as AP from "fp-ts/lib/Apply";
import * as A from "fp-ts/lib/Array";
import { pipe } from "fp-ts/lib/function";
import * as O from "fp-ts/lib/Option";
import * as T from "fp-ts/lib/Task";
import * as TE from "fp-ts/lib/TaskEither";
import * as yargs from "yargs";
import { logger } from "../utils/logger";
import { fetchMetadataXML } from "../utils/metadata";

//
// parse command line
//
const argv = yargs
  .option("idp-metadata-url-env", {
    demandOption: false,
    description: "ENV var name containing IDP Metadata URL",
    normalize: true,
    // eslint-disable-next-line id-blacklist
    string: true
  })
  .option("testenv-metadata-url-env", {
    demandOption: false,
    description: "ENV var name containing TestEnv2 Metadata URL",
    normalize: true,
    // eslint-disable-next-line id-blacklist
    string: true
  })
  .option("cie-metadata-url-env", {
    demandOption: false,
    description: "ENV var name containing CIE Metadata URL",
    normalize: true,
    // eslint-disable-next-line id-blacklist
    string: true
  })
  .help().argv;

interface IIDPSMetadataXML {
  readonly idps?: string;
  readonly xx_testenv2?: string;
  readonly xx_servizicie?: string;
}

const printIdpsMetadata = (
  idpsMetadataENV: string | undefined,
  testEnv2MetadataENV: string | undefined,
  cieMetadataENV: string | undefined
): Promise<IIDPSMetadataXML> => {
  // eslint-disable-next-line functional/immutable-data, @typescript-eslint/no-explicit-any, @typescript-eslint/no-empty-function
  logger.info = (): any => {};
  const maybeIdpsMetadataURL = pipe(
    O.fromNullable(idpsMetadataENV),
    O.chainNullableK(_ => process.env[_]),
    O.map((_: string) =>
      pipe(
        TE.Do,
        TE.bind("idps", () => fetchMetadataXML(_)),
        TE.getOrElseW(() => T.of({}))
      )
    ),
    O.getOrElseW(() => T.of({}))
  );
  const maybeTestEnvMetadataURL = pipe(
    O.fromNullable(testEnv2MetadataENV),
    O.chainNullableK(_ => process.env[_]),
    O.map((_: string) =>
      pipe(
        TE.Do,
        TE.bind("xx_testenv2", () => fetchMetadataXML(`${_}/metadata`)),
        TE.getOrElseW(() => T.of({}))
      )
    ),
    O.getOrElseW(() => T.of({}))
  );
  const maybeCIEMetadataURL = pipe(
    O.fromNullable(cieMetadataENV),
    O.chainNullableK(_ => process.env[_]),
    O.map((_: string) =>
      pipe(
        TE.Do,
        TE.bind("xx_servizicie", () => fetchMetadataXML(_)),
        TE.getOrElseW(() => T.of({}))
      )
    ),
    O.getOrElseW(() => T.of({}))
  );
  return pipe(
    AP.sequenceT(T.ApplicativePar)(
      maybeIdpsMetadataURL,
      maybeTestEnvMetadataURL,
      maybeCIEMetadataURL
    ),

    T.map(A.reduce({}, (prev, current) => ({ ...prev, ...current })))
  )();
};

printIdpsMetadata(
  argv["idp-metadata-url-env"],
  argv["testenv-metadata-url-env"],
  argv["cie-metadata-url-env"]
)
  // eslint-disable-next-line no-console
  .then(metadata => console.log(JSON.stringify(metadata, null, 2)))
  .catch(() => logger.error("Error fetching IDP metadata"));
