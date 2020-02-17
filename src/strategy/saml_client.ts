import * as express from "express";
import { fromNullable } from "fp-ts/lib/Option";
import { SamlConfig } from "passport-saml";
import { SAML } from "passport-saml";
import {
  IExtendedCacheProvider,
  SAMLRequestCacheItem
} from "./redis_cache_provider";
import { PreValidateResponseT, XmlTamperer } from "./spid";

export class CustomSamlClient extends SAML {
  constructor(
    private config: SamlConfig,
    private extededCacheProvider: IExtendedCacheProvider,
    private tamperAuthorizeRequest?: XmlTamperer,
    private preValidateResponse?: PreValidateResponseT
  ) {
    // validateInResponseTo must be set to false to disable
    // internal cacheProvider of passport-saml
    super({ ...config, validateInResponseTo: false });
  }

  /**
   * Custom version of `validatePostResponse` which tampers
   * the generated XML to satisfy SPID protocol constrains
   */
  public validatePostResponse(
    body: { SAMLResponse: string },
    // tslint:disable-next-line: bool-param-default
    callback: (err: Error, profile?: unknown, loggedOut?: boolean) => void
  ): void {
    if (this.preValidateResponse) {
      return this.preValidateResponse(
        this.config,
        body,
        this.extededCacheProvider,
        err => {
          if (err) {
            return callback(err);
          }
          // go on with checks in case no error is found
          return super.validatePostResponse(body, callback);
        }
      );
    }
    super.validatePostResponse(body, callback);
  }

  /**
   * Custom version of `generateAuthorizeRequest` which tampers
   * the generated XML to satisfy SPID protocol constrains
   */
  public generateAuthorizeRequest(
    req: express.Request,
    isPassive: boolean,
    callback: (err: Error, xml?: string) => void
  ): void {
    const newCallback = fromNullable(this.tamperAuthorizeRequest)
      .map(tamperAuthorizeRequest => (e: Error, xml?: string) =>
        xml
          ? tamperAuthorizeRequest(xml)
              .chain(tamperedXml =>
                this.extededCacheProvider.save(tamperedXml, this.config)
              )
              .fold(callback, (tamperedXml: SAMLRequestCacheItem) => {
                // There is a type error on @types/passport-saml
                // Error argument in callback can be null but the
                // Implemented interface expect only Error type
                callback((null as unknown) as Error, tamperedXml.RequestXML);
              })
              .run()
          : callback(e)
      )
      .getOrElse(callback);
    super.generateAuthorizeRequest(req, isPassive, newCallback);
  }
}
