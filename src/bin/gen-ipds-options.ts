#!/usr/bin/env node

import { array } from "fp-ts/lib/Array";
import { toError } from "fp-ts/lib/Either";
import { taskEither } from "fp-ts/lib/TaskEither";
import { tryCatch } from "fp-ts/lib/TaskEither";
import * as fs from "fs-extra";
import { option } from "yargs";
import { IDP_IDS, loadFromRemote } from "../strategies/spidStrategy";
import { log } from "../utils/logger";

//
// parse command line
//

// tslint:disable-next-line: no-any
const argv = option("idp-metadata-url", {
  demandOption: true,
  description: "Url that contains idps metadata infos",
  string: true
})
  .option("out-dir", {
    demandOption: true,
    description: "Output directory to store generated definition files",
    normalize: true,
    string: true
  })
  .option("has-spid-validator-enabled", {
    choices: ["true", "false", "TRUE", "FALSE"],
    default: "false",
    description: "If true spid validator metadata will be added",
    normalize: true,
    string: true
  })
  .help().argv;

const idpOptionsTasks = [
  loadFromRemote(argv["idp-metadata-url"], IDP_IDS)
].concat(
  argv["has-spid-validator-enabled"].toLowerCase() === "true"
    ? [
        loadFromRemote("https://asd.validator.spid.gov.it/metadata.xml", {
          "https://validator.spid.gov.it": "xx_validator"
        })
      ]
    : []
);
// tslint:disable-next-line: no-floating-promises
array
  .sequence(taskEither)(idpOptionsTasks)
  .map(idpOptionsRecords =>
    idpOptionsRecords.reduce((prev, current) => ({ ...prev, ...current }), {})
  )
  .chain(idpOptionsRecord => {
    return tryCatch(() => {
      const outPath = `${argv["out-dir"]}/idpsMetadata.json`;
      if (!fs.existsSync(argv["out-dir"])) {
        fs.mkdirSync(argv["out-dir"]);
      }
      return fs.writeFile(outPath, JSON.stringify(idpOptionsRecord));
    }, toError);
  })
  .mapLeft(_ => {
    log.error("Error on loadFromRemote %s", _);
    process.exit(1);
  })
  .map(_ => log.info("Metatada file generated."))
  .run();
