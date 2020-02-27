import { isLeft, isRight, left } from "fp-ts/lib/Either";
import * as nock from "nock";
import { SPID_IDP_IDENTIFIERS } from "../../config";
import idpsMetadata from "../__mocks__/idps-metatata";
import { fetchIdpsMetadata } from "../metadata";

const mockedIdpsRegistryHost = "https://mocked.registry.net";

describe("fetchIdpsMetadata", () => {
  it("should reject if the IdP metadata are fetched from a wrong path", async () => {
    const notExistingPath = "/not-existing-path";
    nock(mockedIdpsRegistryHost)
      .get(notExistingPath)
      .reply(404);
    const result = await fetchIdpsMetadata(
      mockedIdpsRegistryHost + notExistingPath,
      SPID_IDP_IDENTIFIERS
    ).run();
    expect(isLeft(result)).toBeTruthy();
    expect(result.value).toEqual(expect.any(Error));
  });

  it("should reject an error if the fetch of IdP metadata returns no useful data", async () => {
    const wrongIdpMetadataPath = "/wrong-path";
    nock(mockedIdpsRegistryHost)
      .get(wrongIdpMetadataPath)
      .reply(200, { property: "same value" });
    const result = await fetchIdpsMetadata(
      mockedIdpsRegistryHost + wrongIdpMetadataPath,
      SPID_IDP_IDENTIFIERS
    ).run();
    expect(isLeft(result)).toBeTruthy();
    expect(result.value).toEqual(expect.any(Error));
  });

  it("should reject an error if the fetch of IdP metadata returns an unparsable response", async () => {
    const wrongIdpMetadataPath = "/wrong-path";
    nock(mockedIdpsRegistryHost)
      .get(wrongIdpMetadataPath)
      .reply(200, undefined);
    const result = await fetchIdpsMetadata(
      mockedIdpsRegistryHost + wrongIdpMetadataPath,
      SPID_IDP_IDENTIFIERS
    ).run();
    expect(isLeft(result)).toBeTruthy();
    expect(result.value).toEqual(expect.any(Error));
  });

  it("should resolve with the fetched IdP options", async () => {
    const validIdpMetadataPath = "/correct-path";
    nock(mockedIdpsRegistryHost)
      .get(validIdpMetadataPath)
      .reply(200, idpsMetadata);
    const result = await fetchIdpsMetadata(
      mockedIdpsRegistryHost + validIdpMetadataPath,
      SPID_IDP_IDENTIFIERS
    ).run();
    expect(isRight(result)).toBeTruthy();
  });
});
