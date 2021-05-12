/**
 * SPID Passport strategy
 */
import * as express from "express";
import { array } from "fp-ts/lib/Array";
import { Task, task } from "fp-ts/lib/Task";
import * as t from "io-ts";
import { EmailString, NonEmptyString } from "italia-ts-commons/lib/strings";
import { enumType } from "italia-ts-commons/lib/types";
import { Profile, SamlConfig, VerifiedCallback } from "passport-saml";
import { RedisClient } from "redis";
import { DoneCallbackT } from "..";
import { CIE_IDP_IDENTIFIERS, SPID_IDP_IDENTIFIERS } from "../config";
import {
  PreValidateResponseT,
  SpidStrategy,
  XmlTamperer
} from "../strategy/spid";
import { IDPEntityDescriptor } from "../types/IDPEntityDescriptor";
import { fetchIdpsMetadata } from "./metadata";
import { logSamlCertExpiration, SamlAttributeT } from "./saml";

interface IServiceProviderOrganization {
  URL: string;
  displayName: string;
  name: string;
}

export enum ContactType {
  OTHER = "other",
  BILLING = "billing"
}

export enum EntityType {
  AGGREGATOR = "spid:aggregator",
  AGGREGATED = "spid:aggregated"
}

export enum AggregatorType {
  PublicServicesFullAggregator = "PublicServicesFullAggregator",
  PublicServicesLightAggregator = "PublicServicesLightAggregator",
  PrivateServicesFullAggregator = "PrivateServicesFullAggregator",
  PrivateServicesLightAggregator = "PrivateServicesLightAggregator",
  PublicServicesFullOperator = "PublicServicesFullOperator",
  PublicServicesLightOperator = "PublicServicesLightOperator"
}

export enum AggregatedType {
  Public = "Public",
  PublicOperator = "PublicOperator",
  Private = "Private"
}

const CommonExtension = t.partial({
  FiscalCode: t.string,
  IPACode: t.string,
  VATNumber: t.string
});
type CommonExtension = t.TypeOf<typeof CommonExtension>;

export const LightAggregatorExtension = t.intersection([
  t.interface({
    aggregatorCert: t.string,
    aggregatorType: t.union([
      t.literal(AggregatorType.PrivateServicesLightAggregator),
      t.literal(AggregatorType.PublicServicesLightAggregator),
      t.literal(AggregatorType.PublicServicesLightOperator)
    ])
  }),
  CommonExtension
]);
export type LightAggregatorExtension = t.TypeOf<
  typeof LightAggregatorExtension
>;

const AggregatorExtension = t.intersection([
  t.union([
    t.interface({
      aggregatorType: t.union([
        t.literal(AggregatorType.PrivateServicesFullAggregator),
        t.literal(AggregatorType.PublicServicesFullOperator)
      ])
    }),
    LightAggregatorExtension
  ]),
  CommonExtension
]);
type AggregatorExtension = t.TypeOf<typeof AggregatorExtension>;

const AggregatedExtension = t.intersection([
  t.interface({
    aggregatedType: enumType<AggregatedType>(AggregatedType, "aggregatedType")
  }),
  CommonExtension
]);
type AggregatedExtension = t.TypeOf<typeof AggregatedExtension>;

const IBillingInfo = t.intersection(
  [
    t.interface({
      Sede: t.interface({
        address: t.string,
        cap: t.string,
        city: t.string,
        country: t.string
      })
    }),
    t.partial({
      CodiceEORI: t.string,
      Sede: t.partial({
        number: t.string,
        state: t.string
      }),
      denominazione: t.string,
      fiscalCode: t.string,
      idCodice: t.string,
      idPaese: t.string,
      name: t.string,
      surname: t.string,
      title: t.string
    })
  ],
  "BillingInfo"
);
type IBillingInfo = t.TypeOf<typeof IBillingInfo>;

const ContactPerson = t.union([
  t.interface({
    billing: t.intersection([
      t.interface({
        CessionarioCommittente: IBillingInfo
      }),
      t.partial({
        TerzoIntermediarioSoggettoEmittente: IBillingInfo
      })
    ]),
    company: t.string,
    contactType: t.literal(ContactType.BILLING),
    email: EmailString,
    phone: t.string
  }),
  t.intersection([
    t.interface({
      company: t.string,
      contactType: t.literal(ContactType.OTHER),
      email: EmailString,
      entityType: t.literal(EntityType.AGGREGATOR),
      extensions: AggregatorExtension
    }),
    t.partial({
      phone: t.string
    })
  ]),
  t.intersection([
    t.interface({
      company: t.string,
      contactType: t.literal(ContactType.OTHER),
      email: EmailString,
      entityType: t.literal(EntityType.AGGREGATED),
      extensions: AggregatedExtension
    }),
    t.partial({
      phone: t.string
    })
  ])
]);
type ContactPerson = t.TypeOf<typeof ContactPerson>;
export interface IServiceProviderConfig {
  requiredAttributes: {
    attributes: ReadonlyArray<SamlAttributeT>;
    name: string;
  };
  spidCieUrl?: string;
  spidTestEnvUrl?: string;
  spidValidatorUrl?: string;
  IDPMetadataUrl: string;
  organization: IServiceProviderOrganization;
  contacts?: ReadonlyArray<ContactPerson>;
  publicCert: string;
  strictResponseValidation?: StrictResponseValidationOptions;
}

export type StrictResponseValidationOptions = Record<
  string,
  boolean | undefined
>;

export interface ISpidStrategyOptions {
  idp: { [key: string]: IDPEntityDescriptor | undefined };
  // tslint:disable-next-line: no-any
  sp: SamlConfig & {
    attributes: {
      attributes: {
        attributes: ReadonlyArray<SamlAttributeT>;
        name: string;
      };
      name: string;
    };
  } & {
    organization: IServiceProviderOrganization;
  };
}

/**
 * This method create a Spid Strategy Options object
 * extending the provided SamlOption with the service provider configuration
 * and the idps Options
 */
export function makeSpidStrategyOptions(
  samlConfig: SamlConfig,
  serviceProviderConfig: IServiceProviderConfig,
  idpOptionsRecord: Record<string, IDPEntityDescriptor>
): ISpidStrategyOptions {
  return {
    idp: idpOptionsRecord,
    sp: {
      ...samlConfig,
      attributes: {
        attributes: serviceProviderConfig.requiredAttributes,
        name: "Required attributes"
      },
      identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
      organization: serviceProviderConfig.organization,
      signatureAlgorithm: "sha256"
    }
  };
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
    ).getOrElse({})
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
            ).getOrElse({})
          ]
        : []
    )
    .concat(
      NonEmptyString.is(serviceProviderConfig.spidCieUrl)
        ? [
            fetchIdpsMetadata(
              serviceProviderConfig.spidCieUrl,
              CIE_IDP_IDENTIFIERS
            ).getOrElse({})
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
            ).getOrElse({})
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
      return makeSpidStrategyOptions(
        samlConfig,
        serviceProviderConfig,
        idpOptionsRecord
      );
    });
};

const SPID_STRATEGY_OPTIONS_KEY = "spidStrategyOptions";

/**
 * SPID strategy calls getSamlOptions() for every
 * SAML request. It extracts the options from a
 * shared variable set into the express app.
 */
export const getSpidStrategyOption = (
  app: express.Application
): ISpidStrategyOptions | undefined => {
  return app.get(SPID_STRATEGY_OPTIONS_KEY);
};

/**
 * This method is called to set or update Spid Strategy Options.
 * A selective update is performed to replace only new configurations provided,
 * keeping the others already stored inside the express app.
 */
export const upsertSpidStrategyOption = (
  app: express.Application,
  newSpidStrategyOpts: ISpidStrategyOptions
) => {
  const spidStrategyOptions = getSpidStrategyOption(app);
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
 * SPID strategy factory function.
 */
export function makeSpidStrategy(
  options: ISpidStrategyOptions,
  getSamlOptions: SpidStrategy["getSamlOptions"],
  redisClient: RedisClient,
  tamperAuthorizeRequest?: XmlTamperer,
  tamperMetadata?: XmlTamperer,
  preValidateResponse?: PreValidateResponseT,
  doneCb?: DoneCallbackT
): SpidStrategy {
  return new SpidStrategy(
    { ...options, passReqToCallback: true },
    getSamlOptions,
    (_: express.Request, profile: Profile, done: VerifiedCallback) => {
      // at this point SAML authentication is successful
      // `done` is a passport callback that signals success
      done(null, profile);
    },
    redisClient,
    tamperAuthorizeRequest,
    tamperMetadata,
    preValidateResponse,
    doneCb
  );
}
