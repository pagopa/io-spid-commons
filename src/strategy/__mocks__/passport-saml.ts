import * as express from "express";
import { SamlConfig } from "passport-saml";

const OriginalSAML = require("passport-saml").SAML;

export const mockWrapCallback = jest.fn();

export class SAML {
  public options: any;
  public cacheProvider: any;

  private initialize = OriginalSAML.prototype.initialize;
  constructor(samlConfig: SamlConfig) {
    
    this.options = this.initialize(samlConfig);
    this.cacheProvider = this.options.cacheProvider;
  }

  public validatePostResponse(
    body: { SAMLResponse: string },
    callback: (
      err: Error | null,
      profile?: unknown,
      
      loggedOut?: boolean
    ) => void
  ): void {
    callback(null, {}, false);
  }

  public generateAuthorizeRequest(
    req: express.Request,
    isPassive: boolean,
    isHttpPostBinding: boolean,
    callback: (err: Error | null, xml?: string) => void
  ): void {
    mockWrapCallback(callback);
  }
}

export class Strategy {
  constructor() {
    console.log("Mock Strategy: constructor was called");
  }
}
