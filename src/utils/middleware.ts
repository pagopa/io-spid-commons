/**
 * SPID Passport strategy
 */
import { EmailString, NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import * as express from "express";
import * as A from "fp-ts/lib/Array";
import { pipe } from "fp-ts/lib/function";
import * as T from "fp-ts/lib/Task";
import * as TE from "fp-ts/lib/TaskEither";
import * as t from "io-ts";
import { Profile, SamlConfig, VerifiedCallback } from "passport-saml";
import { RedisClientType, RedisClusterType } from "redis";
import { DoneCallbackT, IExtraLoginRequestParamConfig } from "..";
import { CIE_IDP_IDENTIFIERS, SPID_IDP_IDENTIFIERS } from "../config";
import {
  PreValidateResponseT,
  SpidStrategy,
  XmlAuthorizeTamperer,
  XmlTamperer,
} from "../strategy/spid";
import { IDPEntityDescriptor } from "../types/IDPEntityDescriptor";
import { fetchIdpsMetadata } from "./metadata";
import { logSamlCertExpiration, SamlAttributeT } from "./saml";

interface IServiceProviderOrganization {
  readonly URL: string;
  readonly displayName: string;
  readonly name: string;
}

export enum ContactType {
  OTHER = "other",
}

export enum EntityType {
  AGGREGATOR = "spid:aggregator",
}

export enum AggregatorType {
  PublicServicesFullOperator = "PublicServicesFullOperator",
}

const CommonExtension = t.interface({
  FiscalCode: t.string,
  IPACode: t.string,
  VATNumber: t.string,
});
type CommonExtension = t.TypeOf<typeof CommonExtension>;

const AggregatorExtension = t.intersection([
  t.interface({
    aggregatorType: t.literal(AggregatorType.PublicServicesFullOperator),
  }),
  CommonExtension,
]);
type AggregatorExtension = t.TypeOf<typeof AggregatorExtension>;

const ContactPerson = t.intersection([
  t.interface({
    company: t.string,
    contactType: t.literal(ContactType.OTHER),
    email: EmailString,
    entityType: t.literal(EntityType.AGGREGATOR),
    extensions: AggregatorExtension,
  }),
  t.partial({
    phone: t.string,
  }),
]);
type ContactPerson = t.TypeOf<typeof ContactPerson>;
export interface IServiceProviderConfig {
  readonly requiredAttributes: {
    readonly attributes: ReadonlyArray<SamlAttributeT>;
    readonly name: string;
  };
  readonly spidCieUrl?: string;
  readonly spidCieTestUrl?: string;
  readonly spidTestEnvUrl?: string;
  readonly spidValidatorUrl?: string;
  readonly IDPMetadataUrl: string;
  readonly organization: IServiceProviderOrganization;
  readonly contacts?: ReadonlyArray<ContactPerson>;
  readonly publicCert: string;
  readonly strictResponseValidation?: StrictResponseValidationOptions;
}

export type StrictResponseValidationOptions = Record<
  string,
  boolean | undefined
>;

export interface ISpidStrategyOptions {
  readonly idp: { readonly [key: string]: IDPEntityDescriptor | undefined };
  readonly sp: SamlConfig & {
    readonly attributes: {
      readonly attributes: {
        readonly attributes: ReadonlyArray<SamlAttributeT>;
        readonly name: string;
      };
      readonly name: string;
    };
  } & {
    readonly organization: IServiceProviderOrganization;
  };
}

/**
 * This method create a Spid Strategy Options object
 * extending the provided SamlOption with the service provider configuration
 * and the idps Options
 */
export const makeSpidStrategyOptions = (
  samlConfig: SamlConfig,
  serviceProviderConfig: IServiceProviderConfig,
  idpOptionsRecord: Record<string, IDPEntityDescriptor>
): ISpidStrategyOptions => ({
  idp: idpOptionsRecord,
  sp: {
    ...samlConfig,
    attributes: {
      attributes: serviceProviderConfig.requiredAttributes,
      name: serviceProviderConfig.requiredAttributes.name,
    },
    identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    organization: serviceProviderConfig.organization,
    signatureAlgorithm: "sha256",
  },
});

/**
 * Merge strategy configuration with metadata from IDP.
 *
 * This is used to pass options to the SAML client
 * so it can discriminate between the IDP certificates.
 */
export const getSpidStrategyOptionsUpdater =
  (samlConfig: SamlConfig, serviceProviderConfig: IServiceProviderConfig) =>
  (): T.Task<ISpidStrategyOptions> => {
    const idpOptionsTasks = [
      pipe(
        fetchIdpsMetadata(
          serviceProviderConfig.IDPMetadataUrl,
          SPID_IDP_IDENTIFIERS
        ),
        TE.getOrElseW(() => T.of({}))
      ),
    ]
      .concat(
        pipe(
          NonEmptyString.is(serviceProviderConfig.spidValidatorUrl)
            ? [
                pipe(
                  fetchIdpsMetadata(
                    `${serviceProviderConfig.spidValidatorUrl}/metadata.xml`,
                    {
                      // "https://validator.spid.gov.it" or "http://localhost:8080"
                      [serviceProviderConfig.spidValidatorUrl]: "xx_validator",
                    }
                  ),
                  TE.getOrElseW(() => T.of({}))
                ),
              ]
            : []
        )
      )
      .concat(
        NonEmptyString.is(serviceProviderConfig.spidCieUrl)
          ? [
              pipe(
                fetchIdpsMetadata(
                  serviceProviderConfig.spidCieUrl,
                  CIE_IDP_IDENTIFIERS
                ),
                TE.getOrElseW(() => T.of({}))
              ),
            ]
          : []
      )
      .concat(
        NonEmptyString.is(serviceProviderConfig.spidCieTestUrl)
          ? [
              pipe(
                fetchIdpsMetadata(
                  serviceProviderConfig.spidCieTestUrl,
                  CIE_IDP_IDENTIFIERS
                ),
                TE.getOrElseW(() => T.of({}))
              ),
            ]
          : []
      )
      .concat(
        NonEmptyString.is(serviceProviderConfig.spidTestEnvUrl)
          ? [
              pipe(
                fetchIdpsMetadata(
                  `${serviceProviderConfig.spidTestEnvUrl}/metadata`,
                  {
                    [serviceProviderConfig.spidTestEnvUrl]: "xx_testenv2",
                  }
                ),
                TE.getOrElseW(() => T.of({}))
              ),
            ]
          : []
      );
    return pipe(
      A.sequence(T.ApplicativePar)(idpOptionsTasks),

      T.map(A.reduce({}, (prev, current) => ({ ...prev, ...current }))),
      T.map((idpOptionsRecord) => {
        logSamlCertExpiration(serviceProviderConfig.publicCert);
        return makeSpidStrategyOptions(
          samlConfig,
          serviceProviderConfig,
          idpOptionsRecord
        );
      })
    );
  };

const SPID_STRATEGY_OPTIONS_KEY = "spidStrategyOptions";

/**
 * SPID strategy calls getSamlOptions() for every
 * SAML request. It extracts the options from a
 * shared variable set into the express app.
 */
export const getSpidStrategyOption = (
  app: express.Application
): ISpidStrategyOptions | undefined => app.get(SPID_STRATEGY_OPTIONS_KEY);

/**
 * This method is called to set or update Spid Strategy Options.
 * A selective update is performed to replace only new configurations provided,
 * keeping the others already stored inside the express app.
 */
export const upsertSpidStrategyOption = (
  app: express.Application,
  newSpidStrategyOpts: ISpidStrategyOptions
): void => {
  const spidStrategyOptions = getSpidStrategyOption(app);
  app.set(
    SPID_STRATEGY_OPTIONS_KEY,
    spidStrategyOptions
      ? {
          idp: {
            ...spidStrategyOptions.idp,
            ...newSpidStrategyOpts.idp,
          },
          sp: newSpidStrategyOpts.sp,
        }
      : newSpidStrategyOpts
  );
};

/**
 * SPID strategy factory function.
 */
export const makeSpidStrategy = <T extends Record<string, unknown>>(
  options: ISpidStrategyOptions,
  getSamlOptions: SpidStrategy<T>["getSamlOptions"],
  redisClient: RedisClientType | RedisClusterType,
  tamperAuthorizeRequest?: XmlAuthorizeTamperer,
  tamperMetadata?: XmlTamperer,
  preValidateResponse?: PreValidateResponseT<T>,
  doneCb?: DoneCallbackT<T>,
  extraLoginRequestParamConfig?: IExtraLoginRequestParamConfig<T>
): // eslint-disable-next-line max-params
SpidStrategy<T> =>
  new SpidStrategy<T>(
    { ...options.sp, passReqToCallback: true },
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
    doneCb,
    extraLoginRequestParamConfig
  );
