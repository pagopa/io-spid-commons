// tslint:disable: no-commented-code
// tslint:disable: no-object-mutation
// tslint:disable: no-invalid-this
// tslint:disable: no-submodule-imports
// tslint:disable: no-var-requires
// tslint:disable: variable-name
// tslint:disable: no-any

import * as express from "express";
import {
  AuthenticateOptions,
  AuthorizeOptions,
  SamlConfig,
  VerifyWithoutRequest,
  VerifyWithRequest
} from "passport-saml";
import { Strategy as SamlStrategy } from "passport-saml";
import {
  MultiSamlConfig,
  SamlOptionsCallback
} from "passport-saml/multiSamlStrategy";

const saml = require("passport-saml/lib/passport-saml/saml");

const InMemoryCacheProvider = require("passport-saml/lib/passport-saml/inmemory-cache-provider")
  .CacheProvider;

class MultiSamlStrategy extends SamlStrategy {
  // TODO: types
  private _saml: any;
  private _options: SamlConfig;
  private _getSamlOptions: MultiSamlConfig["getSamlOptions"];

  constructor(
    options: SamlConfig,
    getSamlOptions: MultiSamlConfig["getSamlOptions"],
    verify: VerifyWithRequest | VerifyWithoutRequest
  ) {
    super(options, verify);
    if (!options.requestIdExpirationPeriodMs) {
      // 8 hours
      options.requestIdExpirationPeriodMs = 28800000;
    }
    if (!options.cacheProvider) {
      options.cacheProvider = new InMemoryCacheProvider({
        keyExpirationPeriodMs: options.requestIdExpirationPeriodMs
      });
    }
    this._getSamlOptions = getSamlOptions;
    this._options = options;
  }

  public authenticate(
    req: express.Request,
    options: AuthenticateOptions | AuthorizeOptions
  ): void {
    this._getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return this.error(err);
      }
      this._saml = new saml.SAML(Object.assign({}, this._options, samlOptions));
      super.authenticate(req, options);
    });
  }

  public logout(
    req: express.Request,
    callback: (err: Error | null, url?: string) => void
  ): void {
    this._getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return this.error(err);
      }
      this._saml = new saml.SAML(Object.assign({}, this._options, samlOptions));
      super.logout(req, callback);
    });
  }

  public generateServiceProviderMetadataAsync(
    req: express.Request,
    decryptionCert: string | null,
    signingCert: string | null,
    callback: (err: Error | null, metadata?: string) => void
  ): void {
    this._getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return this.error(err);
      }
      this._saml = new saml.SAML(Object.assign({}, this._options, samlOptions));
      return callback(
        null,
        super.generateServiceProviderMetadata(decryptionCert, signingCert)
      );
    });
  }
}

export default MultiSamlStrategy;
