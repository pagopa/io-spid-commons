// tslint:disable-next-line: ordered-imports
import { isLeft, isRight, left, right } from "fp-ts/lib/Either";
import { NonEmptyArray } from "fp-ts/lib/NonEmptyArray";
import { fromEither } from "fp-ts/lib/TaskEither";
import { NonEmptyString } from "italia-ts-commons/lib/strings";
import { SamlConfig } from "passport-saml";
import { CIE_IDP_IDENTIFIERS, SPID_IDP_IDENTIFIERS } from "../../config";
import { IDPEntityDescriptor } from "../../types/IDPEntityDescriptor";
import * as metadata from "../metadata";
import {
  getSpidStrategyOptionsUpdater,
  IServiceProviderConfig
} from "../middleware";

const mockFetchIdpsMetadata = jest.spyOn(metadata, "fetchIdpsMetadata");

const idpMetadataUrl = "http://ipd.metadata.example/metadata.xml";
const cieMetadataUrl =
  "https://idserver.servizicie.interno.gov.it:8443/idp/shibboleth";
const spidTestEnvUrl = "https://spid-testenv2:8088";

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
  spidCieUrl: cieMetadataUrl,
  spidTestEnvUrl
};
const expectedSamlConfig: SamlConfig = {
  callbackUrl: "http://localhost:3000/callback",
  entryPoint: "http://localhost:3000/acs",
  forceAuthn: true
};

const expectedIdpMetadata: Record<string, IDPEntityDescriptor> = {
  intesaid: {
    cert: (["CERT"] as unknown) as NonEmptyArray<NonEmptyString>,
    entityID: spidTestEnvUrl,
    entryPoint: "https://spid.intesa.it/acs",
    logoutUrl: "https://spid.intesa.it/logout"
  }
};

const expectedCIEIdpMetadata: Record<string, IDPEntityDescriptor> = {
  xx_servizicie_test: {
    cert: (["CERT"] as unknown) as NonEmptyArray<NonEmptyString>,
    entityID:
      "https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/POST/SSO",
    entryPoint:
      "https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/Redirect/SSO",
    logoutUrl: ""
  }
};

const expectedTestenvIdpMetadata: Record<string, IDPEntityDescriptor> = {
  xx_testenv2: {
    cert: (["CERT"] as unknown) as NonEmptyArray<NonEmptyString>,
    entityID: "https://spid-testenv.dev.io.italia.it",
    entryPoint: "https://spid-testenv.dev.io.italia.it/sso",
    logoutUrl: "https://spid-testenv.dev.io.italia.it/slo"
  }
};

describe("getSpidStrategyOptionsUpdater", () => {
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

  beforeEach(() => {
    jest.resetAllMocks();
  });
  afterAll(() => {
    jest.restoreAllMocks();
  });
  it("should returns updated spid options from remote idps metadata", async () => {
    mockFetchIdpsMetadata.mockImplementationOnce(() => {
      return fromEither(
        right<Error, Record<string, IDPEntityDescriptor>>(expectedIdpMetadata)
      );
    });
    mockFetchIdpsMetadata.mockImplementationOnce(() => {
      return fromEither(
        right<Error, Record<string, IDPEntityDescriptor>>(
          expectedCIEIdpMetadata
        )
      );
    });
    mockFetchIdpsMetadata.mockImplementationOnce(() => {
      return fromEither(
        right<Error, Record<string, IDPEntityDescriptor>>(
          expectedTestenvIdpMetadata
        )
      );
    });

    const updatedSpidStrategyOption = await getSpidStrategyOptionsUpdater(
      expectedSamlConfig,
      serviceProviderConfig
    )().run();
    expect(mockFetchIdpsMetadata).toBeCalledTimes(3);
    expect(mockFetchIdpsMetadata).toHaveBeenNthCalledWith(
      1,
      idpMetadataUrl,
      SPID_IDP_IDENTIFIERS
    );
    expect(mockFetchIdpsMetadata).toHaveBeenNthCalledWith(
      2,
      cieMetadataUrl,
      CIE_IDP_IDENTIFIERS
    );
    expect(mockFetchIdpsMetadata).toHaveBeenNthCalledWith(
      3,
      `${spidTestEnvUrl}/metadata`,
      {
        [spidTestEnvUrl]: "xx_testenv2"
      }
    );
    expect(updatedSpidStrategyOption).toHaveProperty("sp", expectedSPProperty);
    expect(updatedSpidStrategyOption).toHaveProperty("idp", {
      ...expectedIdpMetadata,
      ...expectedCIEIdpMetadata,
      ...expectedTestenvIdpMetadata
    });
  });

  it("should returns an error if fetch of remote idp metadata fail", async () => {
    const expectedFetchError = new Error("fetch Error");
    mockFetchIdpsMetadata.mockImplementationOnce(() => {
      return fromEither(
        left<Error, Record<string, IDPEntityDescriptor>>(expectedFetchError)
      );
    });
    // tslint:disable-next-line: no-identical-functions
    mockFetchIdpsMetadata.mockImplementationOnce(() => {
      return fromEither(
        right<Error, Record<string, IDPEntityDescriptor>>(
          expectedCIEIdpMetadata
        )
      );
    });
    // tslint:disable-next-line: no-identical-functions
    mockFetchIdpsMetadata.mockImplementationOnce(() => {
      return fromEither(
        right<Error, Record<string, IDPEntityDescriptor>>(
          expectedTestenvIdpMetadata
        )
      );
    });
    const updatedSpidStrategyOption = await getSpidStrategyOptionsUpdater(
      expectedSamlConfig,
      serviceProviderConfig
    )().run();
    expect(mockFetchIdpsMetadata).toBeCalledTimes(3);
    expect(mockFetchIdpsMetadata).toHaveBeenNthCalledWith(
      1,
      idpMetadataUrl,
      SPID_IDP_IDENTIFIERS
    );
    expect(mockFetchIdpsMetadata).toHaveBeenNthCalledWith(
      2,
      cieMetadataUrl,
      CIE_IDP_IDENTIFIERS
    );
    expect(mockFetchIdpsMetadata).toHaveBeenNthCalledWith(
      3,
      `${spidTestEnvUrl}/metadata`,
      {
        [spidTestEnvUrl]: "xx_testenv2"
      }
    );
    expect(updatedSpidStrategyOption).toHaveProperty("sp", expectedSPProperty);
    expect(updatedSpidStrategyOption).toHaveProperty("idp", {
      ...expectedCIEIdpMetadata,
      ...expectedTestenvIdpMetadata
    });
  });

  it("should call fetchIdpsMetadata only one time if are missing CIE and TestEnv urls", async () => {
    const serviceProviderConfigWithoutOptional: IServiceProviderConfig = {
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
      }
    };
    // tslint:disable-next-line: no-identical-functions
    mockFetchIdpsMetadata.mockImplementationOnce(() => {
      return fromEither(
        right<Error, Record<string, IDPEntityDescriptor>>(expectedIdpMetadata)
      );
    });
    await getSpidStrategyOptionsUpdater(
      expectedSamlConfig,
      serviceProviderConfigWithoutOptional
    )().run();
    expect(mockFetchIdpsMetadata).toBeCalledTimes(1);
    expect(mockFetchIdpsMetadata).toBeCalledWith(
      idpMetadataUrl,
      SPID_IDP_IDENTIFIERS
    );
  });
});
