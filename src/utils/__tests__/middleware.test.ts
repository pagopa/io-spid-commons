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

import getSpidTestIpdOption from "../../providers/xx_testenv2";

const mockFetchIdpsMetadata = jest.spyOn(metadata, "fetchIdpsMetadata");

const idpMetadataUrl = "http://ipd.metadata.example/metadata.xml";
const cieMetadataUrl =
  "https://idserver.servizicie.interno.gov.it:8443/idp/shibboleth";

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
  spidTestEnvUrl: "https://spid-testenv2:8088"
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
    expect(mockFetchIdpsMetadata).toBeCalledTimes(2);
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
    expect(isRight(updatedSpidStrategyOption)).toBeTruthy();
    expect(updatedSpidStrategyOption.value).toHaveProperty(
      "sp",
      expectedSPProperty
    );
    expect(updatedSpidStrategyOption.value).toHaveProperty("idp", {
      ...expectedIdpMetadata,
      ...expectedCIEIdpMetadata,
      xx_testenv2: getSpidTestIpdOption(serviceProviderConfig.spidTestEnvUrl)
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
    const updatedSpidStrategyOption = await getSpidStrategyOptionsUpdater(
      {},
      serviceProviderConfig
    )().run();
    expect(mockFetchIdpsMetadata).toBeCalledTimes(2);
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
    expect(isLeft(updatedSpidStrategyOption)).toBeTruthy();
    expect(updatedSpidStrategyOption.value).toEqual(expectedFetchError);
  });
});
