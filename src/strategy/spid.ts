import * as express from "express";
import { TaskEither } from "fp-ts/lib/TaskEither";
import * as TE from "fp-ts/lib/TaskEither";
import {
  AuthenticateOptions,
  AuthorizeOptions,
  SamlConfig,
  VerifyWithoutRequest,
  VerifyWithRequest,
} from "passport-saml";
import { Strategy as SamlStrategy } from "passport-saml";
import { RedisClientType, RedisClusterType } from "redis";

import { MultiSamlConfig } from "passport-saml/multiSamlStrategy";

import { Second } from "@pagopa/ts-commons/lib/units";
import { pipe } from "fp-ts/lib/function";
import { DoneCallbackT, IExtraLoginRequestParamConfig } from "..";
import { ILollipopParams } from "../types/lollipop";
import {
  getExtendedRedisCacheProvider,
  IExtendedCacheProvider,
  noopCacheProvider,
} from "./redis_cache_provider";
import { CustomSamlClient } from "./saml_client";

export type XmlTamperer = (xml: string) => TaskEither<Error, string>;
export type XmlAuthorizeTamperer = (
  xml: string,
  lollipopParams?: ILollipopParams
) => TaskEither<Error, string>;

export type PreValidateResponseDoneCallbackT = (
  request: string,
  response: string
) => void;

export type PreValidateResponseT = <T extends Record<string, unknown>>(
  samlConfig: SamlConfig,
  body: unknown,
  extendedRedisCacheProvider: IExtendedCacheProvider<T>,
  doneCb: PreValidateResponseDoneCallbackT | undefined,

  callback: (
    err: Error | null,

    isValid?: boolean,
    InResponseTo?: string
  ) => void
) => void;

export class SpidStrategy<
  T extends Record<string, unknown>
> extends SamlStrategy {
  private readonly extendedRedisCacheProvider: IExtendedCacheProvider<T>;

  // eslint-disable-next-line max-params
  constructor(
    private readonly options: SamlConfig,
    private readonly getSamlOptions: MultiSamlConfig["getSamlOptions"],
    verify: VerifyWithRequest | VerifyWithoutRequest,
    private readonly redisClient: RedisClientType | RedisClusterType,
    private readonly tamperAuthorizeRequest?: XmlAuthorizeTamperer,
    private readonly tamperMetadata?: XmlTamperer,
    private readonly preValidateResponse?: PreValidateResponseT,
    private readonly doneCb?: DoneCallbackT,
    private readonly extraLoginRequestParamConfig?: IExtraLoginRequestParamConfig<T>
  ) {
    super(options, verify);
    if (!options.requestIdExpirationPeriodMs) {
      // 15 minutes
      options.requestIdExpirationPeriodMs = 15 * 60 * 1000;
    }

    // use our custom cache provider
    this.extendedRedisCacheProvider = getExtendedRedisCacheProvider(
      this.redisClient,
      this.extraLoginRequestParamConfig?.codec,
      Math.floor(options.requestIdExpirationPeriodMs / 1000) as Second
    );

    // bypass passport-saml cache provider
    options.cacheProvider = noopCacheProvider();
  }

  public authenticate(
    req: express.Request,
    options: AuthenticateOptions | AuthorizeOptions
  ): void {
    this.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return this.error(err);
      }
      const samlService = new CustomSamlClient(
        {
          ...this.options,
          ...samlOptions,
        },
        this.extendedRedisCacheProvider,
        this.extraLoginRequestParamConfig?.requestMapper,
        this.tamperAuthorizeRequest,
        this.preValidateResponse,
        (...args) => (this.doneCb ? this.doneCb(req.ip, ...args) : undefined)
      );
      // we clone the original strategy to avoid race conditions
      // see https://github.com/bergie/passport-saml/pull/426/files
      const strategy = Object.setPrototypeOf(
        {
          ...this,
          _saml: samlService,
        },
        this
      );
      super.authenticate.call(strategy, req, options);
    });
  }

  public logout(
    req: express.Request,
    callback: (err: Error | null, url?: string) => void
  ): void {
    this.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return this.error(err);
      }
      const samlService = new CustomSamlClient(
        {
          ...this.options,
          ...samlOptions,
        },
        this.extendedRedisCacheProvider
      );
      // we clone the original strategy to avoid race conditions
      // see https://github.com/bergie/passport-saml/pull/426/files
      const strategy = Object.setPrototypeOf(
        {
          ...this,
          _saml: samlService,
        },
        this
      );
      super.logout.call(strategy, req, callback);
    });
  }

  public generateServiceProviderMetadataAsync(
    req: express.Request,
    decryptionCert: string | null,
    signingCert: string | null,
    callback: (err: Error | null, metadata?: string) => void
  ): void {
    return this.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return this.error(err);
      }
      const samlService = new CustomSamlClient(
        {
          ...this.options,
          ...samlOptions,
        },
        this.extendedRedisCacheProvider
      );

      // we clone the original strategy to avoid race conditions
      // see https://github.com/bergie/passport-saml/pull/426/files
      const strategy = Object.setPrototypeOf(
        {
          ...this,
          _saml: samlService,
        },
        this
      );

      const originalXml = super.generateServiceProviderMetadata.call(
        strategy,
        decryptionCert,
        signingCert
      );

      return this.tamperMetadata
        ? // Tamper the generated XML for service provider metadata
          pipe(
            this.tamperMetadata(originalXml),
            TE.map((tamperedXml) => callback(null, tamperedXml)),
            TE.mapLeft(callback),
            TE.toUnion
          )()
        : callback(null, originalXml);
    });
  }
}
