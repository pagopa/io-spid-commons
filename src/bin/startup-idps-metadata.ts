#!/usr/bin/env node

import * as AP from "fp-ts/lib/Apply";
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
    string: true
  })
  .option("testenv-metadata-url-env", {
    demandOption: false,
    description: "ENV var name containing TestEnv2 Metadata URL",
    normalize: true,
    string: true
  })
  .option("cie-metadata-url-env", {
    demandOption: false,
    description: "ENV var name containing CIE Metadata URL",
    normalize: true,
    string: true
  })
  .help().argv;

interface IIDPSMetadataXML {
  idps?: string;
  xx_testenv2?: string;
  xx_servizicie?: string;
}

function printIdpsMetadata(
  idpsMetadataENV: string | undefined,
  testEnv2MetadataENV: string | undefined,
  cieMetadataENV: string | undefined
): Promise<IIDPSMetadataXML> {
  // tslint:disable: no-object-mutation no-any no-empty
  logger.info = (): any => {};
  const maybeIdpsMetadataURL = pipe(
    O.fromNullable(idpsMetadataENV),
    O.chainNullableK(_ => process.env[_]),
    O.map((_: string) =>
      pipe(
        fetchMetadataXML(_),
        TE.map(_1 => ({
          idps: _1
        })),
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
        fetchMetadataXML(`${_}/metadata`),
        TE.map(_1 => ({
          xx_testenv2: _1
        })),
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
        fetchMetadataXML(_),
        TE.map(_1 => ({
          xx_servizicie: _1
        })),
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
    T.map(_ => _.reduce((prev, current) => ({ ...prev, ...current }), {}))
  )();
}

printIdpsMetadata(
  argv["idp-metadata-url-env"],
  argv["testenv-metadata-url-env"],
  argv["cie-metadata-url-env"]
)
  // tslint:disable-next-line: no-console
  .then(metadata => console.log(JSON.stringify(metadata, null, 2)))
  .catch(() => logger.error("Error fetching IDP metadata"));
