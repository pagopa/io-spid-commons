// tslint:disable: no-object-mutation
// tslint:disable: no-submodule-imports
// tslint:disable: no-var-requires

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
import { MultiSamlConfig } from "passport-saml/multiSamlStrategy";

const saml = require("passport-saml/lib/passport-saml/saml");

const InMemoryCacheProvider = require("passport-saml/lib/passport-saml/inmemory-cache-provider")
  .CacheProvider;

export type XmlTamperer = (xml: string) => TaskEither<Error, string>;

export type PreValidateResponseT = (
  body: unknown,
  // tslint:disable-next-line: bool-param-default
  callback: (err: Error | null, isValid?: boolean) => void
) => void;

export class MultiSamlStrategy extends SamlStrategy {
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
      this._saml = new saml.SAML(Object.assign({}, this.options, samlOptions));

      // Patch SAML client `validatePostResponse` to intercept
      // and validate the SAMLResponse before the SAML client checks
      if (this.preValidateResponse && req.body && req.body.SAMLResponse) {
        const preValidateResponse = this.preValidateResponse;
        const originalValidatePostResponse = this._saml.validatePostResponse.bind(
          this._saml
        );
        this._saml.validatePostResponse = function(
          // tslint:disable-next-line: no-any
          ...args: readonly any[]
        ): void {
          const originalBody = args[0];
          const originalCallback = args[args.length - 1];
          return preValidateResponse(originalBody, err2 => {
            if (err2) {
              return originalCallback(err2);
            }
            return originalValidatePostResponse.apply(this._saml, args);
          });
        };
      }

      // Patch SAML client `validatePostResponse` to intercept
      // and tamper the generated XML for an authorization request
      else if (this.tamperAuthorizeRequest) {
        const tamperAuthorizeRequest = this.tamperAuthorizeRequest;
        const originalGenerateAuthorizeRequest = this._saml.generateAuthorizeRequest.bind(
          this._saml
        );
        this._saml.generateAuthorizeRequest = function(
          // tslint:disable-next-line: no-any
          ...args: readonly any[]
        ): void {
          const originalCallback = args[args.length - 1];
          const callback = (e: Error, xml: string) => {
            return tamperAuthorizeRequest(xml)
              .fold(
                _ => originalCallback(_),
                xmlStr => originalCallback(e, xmlStr)
              )
              .run();
          };
          return originalGenerateAuthorizeRequest.apply(this._saml, [
            ...args.slice(0, args.length - 1),
            callback
          ]);
        };
      }

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
      this._saml = new saml.SAML(Object.assign({}, this.options, samlOptions));
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
      this._saml = new saml.SAML(Object.assign({}, this.options, samlOptions));

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
