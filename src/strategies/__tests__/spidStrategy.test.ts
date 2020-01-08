import { IDP_IDS, loadFromRemote } from "../spidStrategy";

describe("loadFromRemote", () => {
  it("should reject if the fetch of IdP metadata fails", () => {
    const notExistingUrl = "http://0.1.2.3/index.html";
    const result = loadFromRemote(notExistingUrl, IDP_IDS);
    return expect(result).rejects.toEqual(expect.any(Error));
  });

  it("should reject an error if the fetch of IdP metadata returns no useful data", () => {
    const wrongIdpMetadataUrl = "http://www.example.com";
    const result = loadFromRemote(wrongIdpMetadataUrl, IDP_IDS);
    return expect(result).rejects.toEqual(expect.any(Error));
  });

  it("should resolve with the fetched IdP options", () => {
    const validIdpMetadataUrl =
      "https://raw.githubusercontent.com/teamdigitale/io-backend/164984224-download-idp-metadata/test_idps/spid-entities-idps.xml";
    const result = loadFromRemote(validIdpMetadataUrl, IDP_IDS);
    return expect(result).resolves.toBeTruthy();
  });
});
