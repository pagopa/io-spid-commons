/**
 * This files contains the typescript declaration of module spid-passport.
 */

declare module "spid-passport" {
  import { Strategy } from "passport";
  interface IDPOption {
    // tslint:disable-next-line: readonly-array
    cert: string[];
    entityID: string;
    entryPoint: string;
    logoutUrl: string;
  }

  interface ISpidStrategyOptions {
    idp: { [key: string]: IDPOption | undefined };
    // tslint:disable-next-line: no-any
    sp: any;
  }
  class SpidStrategy<T> extends Strategy {
    constructor(config: ISpidStrategyOptions, _: (
      profile: T,
      done: (err: Error | undefined, info: T) => void
    ) => void );
    // tslint:disable-next-line:no-any
    public logout(req: any, callback?: (err: any, request: any) => void): void;
    public generateServiceProviderMetadata(samlCert: string): string;
    public spidOptions: {
      idp: { [key: string]: IDPOption | undefined };
      // tslint:disable-next-line: no-any
      sp: any;
    };
  }
}
