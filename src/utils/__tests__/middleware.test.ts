// tslint:disable-next-line: ordered-imports
import { isLeft, isRight, right, left } from "fp-ts/lib/Either";
import { NonEmptyArray } from "fp-ts/lib/NonEmptyArray";
import { fromEither } from "fp-ts/lib/TaskEither";
import { NonEmptyString } from "italia-ts-commons/lib/strings";
import { SamlConfig } from "passport-saml";
import { SPID_IDP_IDENTIFIERS } from "../../config";
import { IDPEntityDescriptor } from "../../types/IDPEntityDescriptor";
import * as metadata from "../metadata";
import {
  getSpidStrategyOptionsUpdater,
  IServiceProviderConfig
} from "../middleware";

import getCieIpdOption from "../../providers/xx_servizicie_test";
import getSpidTestIpdOption from "../../providers/xx_testenv2";

const mockFetchIdpsMetadata = jest.spyOn(metadata, "fetchIdpsMetadata");

const idpMetadataUrl = "http://ipd.metadata.example/metadata.xml";
const serviceProviderConfig: IServiceProviderConfig = {
  IDPMetadataUrl: idpMetadataUrl,
  idpMetadataRefreshIntervalMillis: 120000,
  organization: {
    URL: "https://example.com",
    displayName: "Organization display name",
    name: "Organization name"
  },
  publicCert: "",
  requiredAttributes: {
    attributes: [
      "address",
      "email",
      "name",
      "familyName",
      "fiscalNumber",
      "mobilePhone"
    ],
    name: "Required attrs"
  },
  spidTestEnvUrl: "https://spid-testenv2:8088"
};

describe("getSpidStrategyOptionsUpdater", () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });
  afterAll(() => {
    jest.restoreAllMocks();
  });
  it("should returns updated spid options from remote idps metadata", async () => {
    const expectedIdpMetadata: Record<string, IDPEntityDescriptor> = {
      intesaid: {
        cert: (["CERT"] as unknown) as NonEmptyArray<NonEmptyString>,
        entityID: "https://spid.intesa.it",
        entryPoint: "https://spid.intesa.it/acs",
        logoutUrl: "https://spid.intesa.it/logout"
      }
    };
    mockFetchIdpsMetadata.mockImplementation(() => {
      return fromEither(
        right<Error, Record<string, IDPEntityDescriptor>>(expectedIdpMetadata)
      );
    });

    const expectedSamlConfig: SamlConfig = {
      callbackUrl: "http://localhost:3000/callback",
      entryPoint: "http://localhost:3000/acs",
      forceAuthn: true
    };
    const expectedSPProperty = {
      ...expectedSamlConfig,
      attributes: {
        attributes: serviceProviderConfig.requiredAttributes,
        name: "Required attributes"
      },
      identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
      organization: serviceProviderConfig.organization,
      signatureAlgorithm: "sha256"
    };
    const updatedSpidStrategyOption = await getSpidStrategyOptionsUpdater(
      expectedSamlConfig,
      serviceProviderConfig
    )().run();
    expect(mockFetchIdpsMetadata).toBeCalledWith(
      idpMetadataUrl,
      SPID_IDP_IDENTIFIERS
    );
    expect(mockFetchIdpsMetadata).toBeCalledTimes(1);
    expect(isRight(updatedSpidStrategyOption)).toBeTruthy();
    expect(updatedSpidStrategyOption.value).toHaveProperty(
      "sp",
      expectedSPProperty
    );
    expect(updatedSpidStrategyOption.value).toHaveProperty("idp", {
      ...expectedIdpMetadata,
      xx_servizicie_test: getCieIpdOption(),
      xx_testenv2: getSpidTestIpdOption(serviceProviderConfig.spidTestEnvUrl)
    });
  });

  it("should returns an error if fetch of remote idp metadata fail", async () => {
    const expectedFetchError = new Error("fetch Error");
    mockFetchIdpsMetadata.mockImplementation(() => {
      return fromEither(
        left<Error, Record<string, IDPEntityDescriptor>>(expectedFetchError)
      );
    });
    const updatedSpidStrategyOption = await getSpidStrategyOptionsUpdater(
      {},
      serviceProviderConfig
    )().run();
    expect(mockFetchIdpsMetadata).toBeCalledWith(
      idpMetadataUrl,
      SPID_IDP_IDENTIFIERS
    );
    expect(mockFetchIdpsMetadata).toBeCalledTimes(1);
    expect(isLeft(updatedSpidStrategyOption)).toBeTruthy();
    expect(updatedSpidStrategyOption.value).toEqual(expectedFetchError);
  });
});
