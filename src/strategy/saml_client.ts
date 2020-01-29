import * as express from "express";
import { SamlConfig } from "passport-saml";
import { SAML } from "passport-saml";
import { PreValidateResponseT, XmlTamperer } from "./spid";

export class CustomSamlClient extends SAML {
  constructor(
    private config: SamlConfig,
    private tamperAuthorizeRequest?: XmlTamperer,
    private preValidateResponse?: PreValidateResponseT
  ) {
    super(config);
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
      return this.preValidateResponse(this.config, body, err => {
        if (err) {
          return callback(err);
        }
        // go on with checks in case no error is found
        return super.validatePostResponse(body, callback);
      });
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
    if (this.tamperAuthorizeRequest) {
      const tamperAuthorizeRequest = this.tamperAuthorizeRequest;
      const alteredCallback = (e: Error, xml?: string) => {
        return xml
          ? tamperAuthorizeRequest(xml)
              .fold(callback, tamperedXml => callback(e, tamperedXml))
              .run()
          : callback(e);
      };
      return super.generateAuthorizeRequest(req, isPassive, alteredCallback);
    }
    super.generateAuthorizeRequest(req, isPassive, callback);
  }
}
