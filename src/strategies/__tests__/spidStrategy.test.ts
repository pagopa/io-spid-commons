import * as nock from "nock";
import spidEntitiesIdps from "../../__mocks__/spid-entities-idps";
import { IDP_IDS, loadFromRemote } from "../spidStrategy";

const mockedIdpsRegistryHost = "https://mocked.registry.net";

describe("loadFromRemote", () => {
  it("should reject if the fetch of IdP metadata fails", () => {
    const notExistingPath = "/not-existing-path";
    nock(mockedIdpsRegistryHost)
      .get(notExistingPath)
      .reply(404);
    const result = loadFromRemote(
      mockedIdpsRegistryHost + notExistingPath,
      IDP_IDS
    );
    return expect(result).rejects.toEqual(expect.any(Error));
  });

  it("should reject an error if the fetch of IdP metadata returns no useful data", () => {
    const wrongIdpMetadataPath = "/wrong-path";
    nock(mockedIdpsRegistryHost)
      .get(wrongIdpMetadataPath)
      .reply(200, { property: "same value" });
    const result = loadFromRemote(
      mockedIdpsRegistryHost + wrongIdpMetadataPath,
      IDP_IDS
    );
    return expect(result).rejects.toEqual(expect.any(Error));
  });

  it("should resolve with the fetched IdP options", () => {
    const validIdpMetadataPath = "/correct-path";
    nock(mockedIdpsRegistryHost)
      .get(validIdpMetadataPath)
      .reply(200, spidEntitiesIdps);
    const result = loadFromRemote(
      mockedIdpsRegistryHost + validIdpMetadataPath,
      IDP_IDS
    );
    return expect(result).resolves.toBeTruthy();
  });
});
