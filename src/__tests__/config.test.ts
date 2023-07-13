import { IDP_NAMES } from "../config";
describe("IDP_NAMES", () => {
  it("should return the IdP name if a valid entityId is provided", () => {
    const aValidEntityID = "https://id.eht.eu";
    const idpName = IDP_NAMES[aValidEntityID];
    expect(idpName).toBeDefined();
  });

  it("should return undefined if a invalid entityId is provided", () => {
    const aInvalidEntityID = "https://invalid.entity.id";
    const idpName = IDP_NAMES[aInvalidEntityID];
    expect(idpName).toBeUndefined();
  });
});
