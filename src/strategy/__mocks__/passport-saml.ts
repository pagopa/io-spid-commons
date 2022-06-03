// eslint-disable @typescript-eslint/no-explicit-any
import * as express from "express";
import { SamlConfig } from "passport-saml";

const OriginalSAML = require("passport-saml").SAML;

export const mockWrapCallback = jest.fn();

// eslint-disable max-classes-per-file
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
    // eslint-disable-next-line no-console
    console.log("Mock Strategy: constructor was called");
  }
}
