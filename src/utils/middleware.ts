/**
 * SPID Passport strategy
 */
// tslint:disable-next-line: no-submodule-imports
import { EmailString, NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import * as express from "express";
import * as A from "fp-ts/lib/Array";
import { flow, pipe } from "fp-ts/lib/function";
import * as O from "fp-ts/lib/Option";
import * as T from "fp-ts/lib/Task";
import * as TE from "fp-ts/lib/TaskEither";
import * as t from "io-ts";
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
  OTHER = "other"
}

export enum EntityType {
  AGGREGATOR = "spid:aggregator"
}

export enum AggregatorType {
  PublicServicesFullOperator = "PublicServicesFullOperator"
}

const CommonExtension = t.interface({
  FiscalCode: t.string,
  IPACode: t.string,
  VATNumber: t.string
});
type CommonExtension = t.TypeOf<typeof CommonExtension>;

const AggregatorExtension = t.intersection([
  t.interface({
    aggregatorType: t.literal(AggregatorType.PublicServicesFullOperator)
  }),
  CommonExtension
]);
type AggregatorExtension = t.TypeOf<typeof AggregatorExtension>;

const ContactPerson = t.intersection([
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
  spidSamlCheckUrl?: string;
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
        name: serviceProviderConfig.requiredAttributes.name
      },
      identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
      organization: serviceProviderConfig.organization,
      signatureAlgorithm: "sha256"
    }
  };
}

// Just an utility to normalize idp metadata fetching task
const maybeIdpMetadata = (
  url: string | undefined,
  idpMetadataUrl: string,
  idpConfig: Record<string, string>
): O.Option<T.Task<Record<string, IDPEntityDescriptor>>> =>
  pipe(
    url,
    O.fromNullable,
    O.map(
      flow(
        NonEmptyString.decode,
        TE.fromEither,
        TE.chainW(_ => fetchIdpsMetadata(idpMetadataUrl, idpConfig)),
        // idp metadadata fetching won't fail but returning an empty dataset
        TE.getOrElseW(() => T.of({}))
      )
    )
  );

// Fetch every and only metatadata for IDPs to be mount
const fetchAllIdpsMetadata = (serviceProviderConfig: IServiceProviderConfig) =>
  [
    // Production SPID IDP metadata
    maybeIdpMetadata(
      serviceProviderConfig.IDPMetadataUrl,
      `${serviceProviderConfig.IDPMetadataUrl}`,
      SPID_IDP_IDENTIFIERS
    ),
    // Production CIE IDP metadata
    maybeIdpMetadata(
      serviceProviderConfig.spidCieUrl,
      `${serviceProviderConfig.spidCieUrl}`,
      CIE_IDP_IDENTIFIERS
    ),
    // Development Saml Validator IDP metadata
    maybeIdpMetadata(
      serviceProviderConfig.spidValidatorUrl,
      `${serviceProviderConfig.spidValidatorUrl}/metadata.xml`,
      {
        [`${serviceProviderConfig.spidValidatorUrl}`]: "xx_validator"
      }
    ),
    // Development Spid-Testenv2 IDP metadata
    maybeIdpMetadata(
      serviceProviderConfig.spidTestEnvUrl,
      `${serviceProviderConfig.spidTestEnvUrl}/metadata`,
      {
        [`${serviceProviderConfig.spidTestEnvUrl}`]: "xx_testenv2"
      }
    ),
    // Development Spid-Saml-Check IDP metadata
    maybeIdpMetadata(
      serviceProviderConfig.spidSamlCheckUrl,
      `${serviceProviderConfig.spidSamlCheckUrl}/metadata.xml`,
      {
        [`${serviceProviderConfig.spidSamlCheckUrl}`]: "xx_samlcheck"
      }
    )
  ]
    .filter(O.isSome)
    .map(e => e.value);

/**
 * Merge strategy configuration with metadata from IDP.
 *
 * This is used to pass options to the SAML client
 * so it can discriminate between the IDP certificates.
 */
export const getSpidStrategyOptionsUpdater = (
  samlConfig: SamlConfig,
  serviceProviderConfig: IServiceProviderConfig
): (() => T.Task<ISpidStrategyOptions>) => () =>
  pipe(
    serviceProviderConfig,
    fetchAllIdpsMetadata,
    A.sequence(T.ApplicativePar),
    // tslint:disable-next-line: no-inferred-empty-object-type
    T.map(A.reduce({}, (prev, current) => ({ ...prev, ...current }))),
    T.map(idpOptionsRecord => {
      logSamlCertExpiration(serviceProviderConfig.publicCert);
      return makeSpidStrategyOptions(
        samlConfig,
        serviceProviderConfig,
        idpOptionsRecord
      );
    })
  );

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
