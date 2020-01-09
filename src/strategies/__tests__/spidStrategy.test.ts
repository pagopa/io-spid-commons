import { isLeft, isRight } from "fp-ts/lib/Either";
import * as nock from "nock";
import spidEntitiesIdps from "../../__mocks__/spid-entities-idps";
import * as idpLoader from "../../utils/idpLoader";
import { IDP_IDS, loadFromRemote } from "../spidStrategy";

const mockedIdpsRegistryHost = "https://mocked.registry.net";

describe("loadFromRemote", () => {
  it("should reject if the fetch of IdP metadata fails", async () => {
    const fetchError = new Error("An error occurred on IdP metadata fetch");
    const path = "fetch-rejecting-path";
    jest
      .spyOn(idpLoader, "fetchIdpMetadata")
      .mockImplementationOnce(() => Promise.reject(fetchError));
    const result = await loadFromRemote(path, IDP_IDS).run();
    expect(isLeft(result)).toBeTruthy();
    expect(result.value).toEqual(expect.any(Error));
  });

  it("should reject if the IdP metadata are fetched from a wrong path", async () => {
    const notExistingPath = "/not-existing-path";
    nock(mockedIdpsRegistryHost)
      .get(notExistingPath)
      .reply(404);
    const result = await loadFromRemote(
      mockedIdpsRegistryHost + notExistingPath,
      IDP_IDS
    ).run();
    expect(isLeft(result)).toBeTruthy();
    expect(result.value).toEqual(expect.any(Error));
  });

  it("should reject an error if the fetch of IdP metadata returns no useful data", async () => {
    const wrongIdpMetadataPath = "/wrong-path";
    nock(mockedIdpsRegistryHost)
      .get(wrongIdpMetadataPath)
      .reply(200, { property: "same value" });
    const result = await loadFromRemote(
      mockedIdpsRegistryHost + wrongIdpMetadataPath,
      IDP_IDS
    ).run();
    expect(isLeft(result)).toBeTruthy();
    expect(result.value).toEqual(expect.any(Error));
  });

  it("should resolve with the fetched IdP options", async () => {
    const validIdpMetadataPath = "/correct-path";
    nock(mockedIdpsRegistryHost)
      .get(validIdpMetadataPath)
      .reply(200, spidEntitiesIdps);
    const result = await loadFromRemote(
      mockedIdpsRegistryHost + validIdpMetadataPath,
      IDP_IDS
    ).run();
    expect(isRight(result)).toBeTruthy();
  });
});
