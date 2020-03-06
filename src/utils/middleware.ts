/**
 * SPID Passport strategy
 */
import * as express from "express";
import { array } from "fp-ts/lib/Array";
import { Task, task } from "fp-ts/lib/Task";
import { NonEmptyString } from "italia-ts-commons/lib/strings";
import { Profile, SamlConfig, VerifiedCallback } from "passport-saml";
import { RedisClient } from "redis";
import { CIE_IDP_IDENTIFIERS, SPID_IDP_IDENTIFIERS } from "../config";
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
  spidCieUrl?: string;
  spidTestEnvUrl?: string;
  spidValidatorUrl?: string;
  IDPMetadataUrl: string;
  organization: {
    URL: string;
    displayName: string;
    name: string;
  };
  publicCert: string;
  idpMetadataRefreshIntervalMillis: number;
  strictResponseValidation?: StrictResponseValidationOptions;
}

export type StrictResponseValidationOptions = Record<
  string,
  boolean | undefined
>;

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
): (() => Task<ISpidStrategyOptions>) => () => {
  const idpOptionsTasks = [
    fetchIdpsMetadata(
      serviceProviderConfig.IDPMetadataUrl,
      SPID_IDP_IDENTIFIERS
    ).fold(
      () => ({}),
      _ => _
    )
  ]
    .concat(
      NonEmptyString.is(serviceProviderConfig.spidValidatorUrl)
        ? [
            fetchIdpsMetadata(
              `${serviceProviderConfig.spidValidatorUrl}/metadata.xml`,
              {
                // "https://validator.spid.gov.it" or "http://localhost:8080"
                [serviceProviderConfig.spidValidatorUrl]: "xx_validator"
              }
            ).fold(
              () => ({}),
              _ => _
            )
          ]
        : []
    )
    .concat(
      NonEmptyString.is(serviceProviderConfig.spidCieUrl)
        ? [
            fetchIdpsMetadata(
              serviceProviderConfig.spidCieUrl,
              CIE_IDP_IDENTIFIERS
            ).fold(
              () => ({}),
              _ => _
            )
          ]
        : []
    )
    .concat(
      NonEmptyString.is(serviceProviderConfig.spidTestEnvUrl)
        ? [
            fetchIdpsMetadata(
              `${serviceProviderConfig.spidTestEnvUrl}/metadata`,
              {
                [serviceProviderConfig.spidTestEnvUrl]: "xx_testenv2"
              }
            ).fold(
              () => ({}),
              _ => _
            )
          ]
        : []
    );
  return array
    .sequence(task)(idpOptionsTasks)
    .map(idpOptionsRecords =>
      idpOptionsRecords.reduce((prev, current) => ({ ...prev, ...current }), {})
    )
    .map(idpOptionsRecord => {
      logSamlCertExpiration(serviceProviderConfig.publicCert);
      return {
        idp: idpOptionsRecord,
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
 * upsertSpidStrategyOption() is called to set or update Spid Strategy Options.
 * A selective update is performed to replace only new configurations provided,
 * keeping the others already stored inside the express app.
 */
export const upsertSpidStrategyOption = (
  app: express.Application,
  newSpidStrategyOpts: ISpidStrategyOptions
) => {
  const spidStrategyOptions: ISpidStrategyOptions | undefined = app.get(
    SPID_STRATEGY_OPTIONS_KEY
  );
  app.set(
    SPID_STRATEGY_OPTIONS_KEY,
    spidStrategyOptions
      ? {
          idp: {
            ...spidStrategyOptions.idp,
            ...newSpidStrategyOpts.idp
          },
          sp: newSpidStrategyOpts.sp
        }
      : newSpidStrategyOpts
  );
};

/**
 * SPID strategy calls getSamlOptions() for every
 * SAML request. It extracts the options from a
 * shared variable set into the express app.
 */
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
