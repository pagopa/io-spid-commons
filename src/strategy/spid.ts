import * as express from "express";
import { TaskEither } from "fp-ts/lib/TaskEither";
import {
  AuthenticateOptions,
  AuthorizeOptions,
  SamlConfig,
  VerifyWithoutRequest,
  VerifyWithRequest
} from "passport-saml";
import { Strategy as SamlStrategy } from "passport-saml";

// tslint:disable-next-line: no-submodule-imports
import { MultiSamlConfig } from "passport-saml/multiSamlStrategy";
import { CustomSamlClient } from "./saml";

// tslint:disable-next-line: no-submodule-imports no-var-requires
const saml = require("passport-saml/lib/passport-saml/saml");

// tslint:disable-next-line: no-submodule-imports no-var-requires
const InMemoryCacheProvider = require("passport-saml/lib/passport-saml/inmemory-cache-provider")
  .CacheProvider;

export type XmlTamperer = (xml: string) => TaskEither<Error, string>;

export type PreValidateResponseT = (
  body: unknown,
  // tslint:disable-next-line: bool-param-default
  callback: (err: Error | null, isValid?: boolean) => void
) => void;

export class SpidStrategy extends SamlStrategy {
  // tslint:disable-next-line: variable-name no-any
  private _saml: any;

  constructor(
    private options: SamlConfig,
    private getSamlOptions: MultiSamlConfig["getSamlOptions"],
    verify: VerifyWithRequest | VerifyWithoutRequest,
    private tamperAuthorizeRequest?: XmlTamperer,
    private tamperMetadata?: XmlTamperer,
    private preValidateResponse?: PreValidateResponseT
  ) {
    super(options, verify);
    if (!options.requestIdExpirationPeriodMs) {
      // 8 hours
      options.requestIdExpirationPeriodMs = 28800000;
    }
    if (!options.cacheProvider) {
      // WARNING: you cannot use this one if you have
      // multiple instances of the express app running
      // (ie. multiple pods on Kubernetes).
      // Use a RedisCacheProvider instead which can be
      // safely shared between instances.
      options.cacheProvider = new InMemoryCacheProvider({
        keyExpirationPeriodMs: options.requestIdExpirationPeriodMs
      });
    }
  }

  public authenticate(
    req: express.Request,
    options: AuthenticateOptions | AuthorizeOptions
  ): void {
    this.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return this.error(err);
      }
      // tslint:disable-next-line: no-object-mutation
      this._saml = new CustomSamlClient(
        { ...this.options, ...samlOptions },
        this.tamperAuthorizeRequest,
        this.preValidateResponse
      );
      super.authenticate(req, options);
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
      // tslint:disable-next-line: no-object-mutation
      this._saml = new CustomSamlClient({ ...this.options, ...samlOptions });
      super.logout(req, callback);
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
      // tslint:disable-next-line: no-object-mutation
      this._saml = new CustomSamlClient({ ...this.options, ...samlOptions });

      const originalXml = super.generateServiceProviderMetadata(
        decryptionCert,
        signingCert
      );

      return this.tamperMetadata
        ? // Tamper the generated XML for service provider metadata
          this.tamperMetadata(originalXml)
            .fold(
              e => callback(e),
              tamperedXml => callback(null, tamperedXml)
            )
            .run()
        : callback(null, originalXml);
    });
  }
}
