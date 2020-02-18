/**
 * SPID Passport strategy
 */
import * as express from "express";
import { array } from "fp-ts/lib/Array";
import { taskEither, TaskEither } from "fp-ts/lib/TaskEither";
import { Profile, SamlConfig, VerifiedCallback } from "passport-saml";
import { RedisClient } from "redis";
import { SPID_IDP_IDENTIFIERS } from "../config";
import getCieIpdOption from "../providers/xx_servizicie_test";
import getSpidTestIpdOption from "../providers/xx_testenv2";
import {
  PreValidateResponseT,
  SpidStrategy,
  XmlTamperer
} from "../strategy/spid";
import { IDPEntityDescriptor } from "../types/IDPEntityDescriptor";
import { logger } from "./logger";
import { fetchIdpsMetadata } from "./metadata";
import { logSamlCertExpiration, SamlAttributeT } from "./saml";

export interface IServiceProviderConfig {
  requiredAttributes: {
    attributes: ReadonlyArray<SamlAttributeT>;
    name: string;
  };
  spidTestEnvUrl: string;
  IDPMetadataUrl: string;
  organization: {
    URL: string;
    displayName: string;
    name: string;
  };
  publicCert: string;
  hasSpidValidatorEnabled: boolean;
  idpMetadataRefreshIntervalMillis: number;
}

export interface ISpidStrategyOptions {
  idp: { [key: string]: IDPEntityDescriptor | undefined };
  // tslint:disable-next-line: no-any
  sp: SamlConfig;
}

/**
 * Merge strategy configuration with metadata from IDP.
 *
 * This is used to pass options to the SAML client
 * so it can discriminate between the IDP certificates.
 */
export const getSpidStrategyOptionsUpdater = (
  samlConfig: SamlConfig,
  serviceProviderConfig: IServiceProviderConfig
): (() => TaskEither<Error, ISpidStrategyOptions>) => () => {
  const idpOptionsTasks = [
    fetchIdpsMetadata(
      serviceProviderConfig.IDPMetadataUrl,
      SPID_IDP_IDENTIFIERS
    )
  ].concat(
    serviceProviderConfig.hasSpidValidatorEnabled
      ? [
          fetchIdpsMetadata("http://spid-saml-check:8080/metadata.xml", {
            // TODO: must be a configuration param
            // "https://validator.spid.gov.it": "xx_validator"
            "http://localhost:8080": "xx_validator"
          })
        ]
      : []
  );
  return array
    .sequence(taskEither)(idpOptionsTasks)
    .map(idpOptionsRecords =>
      idpOptionsRecords.reduce((prev, current) => ({ ...prev, ...current }), {})
    )
    .map(idpOptionsRecord => {
      logSamlCertExpiration(serviceProviderConfig.publicCert);
      return {
        idp: {
          ...idpOptionsRecord,
          xx_servizicie_test: getCieIpdOption(),
          xx_testenv2: getSpidTestIpdOption(
            serviceProviderConfig.spidTestEnvUrl
          )
        },
        sp: {
          ...samlConfig,
          attributes: {
            attributes: serviceProviderConfig.requiredAttributes,
            name: "Required attributes"
          },
          identifierFormat:
            "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
          organization: serviceProviderConfig.organization,
          signatureAlgorithm: "sha256"
        }
      };
    });
};

const SPID_STRATEGY_OPTIONS_KEY = "spidStrategyOptions";

/**
 * SPID strategy calls getSamlOptions() for every
 * SAML request. It extracts the options from a
 * shared variable set into the express app.
 */
export const setSpidStrategyOption = (
  app: express.Application,
  opts: ISpidStrategyOptions
) => {
  app.set(SPID_STRATEGY_OPTIONS_KEY, opts);
};

export const getSpidStrategyOption = (
  app: express.Application
): ISpidStrategyOptions => {
  return app.get(SPID_STRATEGY_OPTIONS_KEY);
};

/**
 * SPID strategy factory function.
 */
export function makeSpidStrategy(
  options: ISpidStrategyOptions,
  getSamlOptions: SpidStrategy["getSamlOptions"],
  redisClient: RedisClient,
  tamperAuthorizeRequest?: XmlTamperer,
  tamperMetadata?: XmlTamperer,
  preValidateResponse?: PreValidateResponseT
): SpidStrategy {
  return new SpidStrategy(
    { ...options, passReqToCallback: true },
    getSamlOptions,
    (_: express.Request, profile: Profile, done: VerifiedCallback) => {
      logger.debug(profile.getAssertionXml());
      // at this point SAML authentication is successful
      // `done` is a passport callback that signals success
      done(null, profile);
    },
    redisClient,
    tamperAuthorizeRequest,
    tamperMetadata,
    preValidateResponse
  );
}
