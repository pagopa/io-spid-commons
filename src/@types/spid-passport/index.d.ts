/**
 * This files contains the typescript declaration of module spid-passport.
 */

declare module "spid-passport";

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

declare class SpidStrategy {
  public spidOptions: {
    idp: { [key: string]: IDPOption | undefined };
    // tslint:disable-next-line: no-any
    sp: any;
  };
  constructor(
    config: ISpidStrategyOptions,
    // tslint:disable-next-line: no-any
    _: (profile: any, done: (err: Error | undefined, info: any) => void) => void
  );
  // tslint:disable-next-line:no-any
  public logout(req: any, callback?: (err: any, request: any) => void): void;
  public generateServiceProviderMetadata(samlCert: string): string;
}
