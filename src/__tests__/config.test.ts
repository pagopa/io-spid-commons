import { pipe } from "fp-ts/lib/function";
import {
  CIE_IDP_IDENTIFIERS,
  IDP_NAMES,
  Issuer,
  SPID_IDP_IDENTIFIERS,
} from "../config";
import * as RA from "fp-ts/lib/ReadonlyArray";
import * as E from "fp-ts/Either";
describe("IDP_NAMES", () => {
  it("should return the IdP name if a valid entityId is provided", () => {
    const aValidEntityID = "https://id.eht.eu";
    const idpName = IDP_NAMES[aValidEntityID];
    expect(idpName).toBeDefined();
  });

  it("should return undefined if a invalid entityId is provided", () => {
    const aInvalidEntityID = "https://invalid.entity.id" as Issuer;
    const idpName = IDP_NAMES[aInvalidEntityID];
    expect(idpName).toBeUndefined();
  });

  it("All the possible entityId should be mapped as IdP names", () => {
    const possibleEntityID = [
      ...Object.keys(SPID_IDP_IDENTIFIERS),
      ...Object.keys(CIE_IDP_IDENTIFIERS),
    ] as ReadonlyArray<Issuer>;
    pipe(
      possibleEntityID,
      RA.map((entityId) => IDP_NAMES[entityId]),
      RA.map((entityName) => expect(entityName).toBeDefined())
    );
  });
});

describe("Issuer", () => {
  it("Should successfully decode any possible EntityId", () => {
    const possibleEntityID = [
      ...Object.keys(SPID_IDP_IDENTIFIERS),
      ...Object.keys(CIE_IDP_IDENTIFIERS),
    ];
    pipe(
      possibleEntityID,
      RA.map(Issuer.decode),
      RA.every(E.isRight),
      (result) => expect(result).toBeTruthy()
    );
  });
});
