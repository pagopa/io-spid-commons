import { IDPEntityDescriptor } from "../types/IDPEntityDescriptor";

import { NonEmptyArray } from "fp-ts/lib/NonEmptyArray";

import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";

export const mockIdpMetadata: Record<string, IDPEntityDescriptor> = {
  posteid: {
    cert: (["CERT"] as unknown) as NonEmptyArray<NonEmptyString>,
    entityID: "https://posteid.poste.it",
    entryPoint: "https://posteid.poste.it/acs",
    logoutUrl: "https://posteid.poste.it/logout"
  }
};

export const mockCIEIdpMetadata: Record<string, IDPEntityDescriptor> = {
  xx_servizicie_test: {
    cert: (["CERT"] as unknown) as NonEmptyArray<NonEmptyString>,
    entityID:
      "https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/POST/SSO",
    entryPoint:
      "https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/Redirect/SSO",
    logoutUrl: ""
  }
};

export const mockCIETestIdpMetadata: Record<string, IDPEntityDescriptor> = {
  xx_servizicie_coll: {
    cert: (["CERT"] as unknown) as NonEmptyArray<NonEmptyString>,
    entityID:
      "https://collaudo.idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO",
    entryPoint:
      "https://collaudo.idserver.servizicie.interno.gov.it/idp/profile/SAML2/Redirect/SLO",
    logoutUrl: ""
  }
};

export const mockTestenvIdpMetadata: Record<string, IDPEntityDescriptor> = {
  xx_testenv2: {
    cert: (["CERT"] as unknown) as NonEmptyArray<NonEmptyString>,
    entityID: "https://spid-testenv.dev.io.italia.it",
    entryPoint: "https://spid-testenv.dev.io.italia.it/sso",
    logoutUrl: "https://spid-testenv.dev.io.italia.it/slo"
  }
};
