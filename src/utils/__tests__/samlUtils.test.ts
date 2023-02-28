import * as jose from "jose";
import { Builder, parseStringPromise } from "xml2js";
import {
  DEFAULT_LOLLIPOP_HASH_ALGORITHM,
  ILollipopParams
} from "../../types/lollipop";
import { getAuthorizeRequestTamperer, ISSUER_FORMAT } from "../samlUtils";
import { samlRequest, samlRequestWithID } from "../__mocks__/saml";
import * as E from "fp-ts/lib/Either";
import { JwkPublicKey } from "@pagopa/ts-commons/lib/jwk";
const builder = new Builder({
  xmldec: { encoding: undefined, version: "1.0" }
});

const samlConfigMock = {
  issuer: "ISSUER"
} as any;

const aJwkPubKey: JwkPublicKey = {
  kty: "EC",
  crv: "secp256k1",
  x: "Q8K81dZcC4DdKl52iW7bT0ubXXm2amN835M_v5AgpSE",
  y: "lLsw82Q414zPWPluI5BmdKHK6XbFfinc8aRqbZCEv0A"
};

const lollipopParamsMock: ILollipopParams = {
  pubKey: aJwkPubKey
};

const aSamlRequestID = "aSamlRequestID";

const fakeXml = `<?xml version="1.0"?>
<samlp:Fake xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="ID" Version="2.0" IssueInstant="2020-02-26T07:27:00Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Destination="http://localhost:8080/samlsso" ForceAuthn="true" AssertionConsumerServiceURL="http://localhost:3000/acs" AttributeConsumingServiceIndex="0">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" NameQualifier="https://spid.agid.gov.it/cd" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">
        https://spid.agid.gov.it/cd
    </saml:Issuer>
    <samlp:NameIDPolicy xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>
    <samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Comparison="exact">
        <saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            https://www.spid.gov.it/SpidL2
        </saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
</samlp:Fake>`;
describe("getAuthorizeRequestTamperer", () => {
  it("should Tamper an AuthNRequest overriding properties to be compatible with SPID protocol", async () => {
    const authRequestTamperer = getAuthorizeRequestTamperer(
      builder,
      samlConfigMock
    );
    const result = await authRequestTamperer(
      samlRequestWithID(aSamlRequestID)
    )();
    expect(E.isRight(result)).toBeTruthy();
    if (E.isRight(result)) {
      const parsedXml = await parseStringPromise(result.right);
      const authnRequest = parsedXml["samlp:AuthnRequest"];
      expect(authnRequest.$.ID).toEqual(aSamlRequestID);
      expect(
        authnRequest["samlp:NameIDPolicy"][0].$.AllowCreate
      ).toBeUndefined();
      expect(authnRequest["saml:Issuer"][0].$.NameQualifier).toEqual(
        samlConfigMock.issuer
      );
      expect(authnRequest["saml:Issuer"][0].$.Format).toEqual(ISSUER_FORMAT);
    }
  });

  it("should Tamper an AuthNRequest overriding ID property for authorized lollipop users", async () => {
    const authRequestTamperer = getAuthorizeRequestTamperer(
      builder,
      samlConfigMock
    );
    const result = await authRequestTamperer(samlRequest, lollipopParamsMock)();
    expect(E.isRight(result)).toBeTruthy();
    if (E.isRight(result)) {
      const parsedXml = await parseStringPromise(result.right);
      const authnRequest = parsedXml["samlp:AuthnRequest"];
      const thumbprint = await jose.calculateJwkThumbprint(
        lollipopParamsMock.pubKey,
        DEFAULT_LOLLIPOP_HASH_ALGORITHM
      );
      expect(authnRequest.$.ID).toEqual(
        `${DEFAULT_LOLLIPOP_HASH_ALGORITHM}-${thumbprint}`
      );
      expect(
        authnRequest["samlp:NameIDPolicy"][0].$.AllowCreate
      ).toBeUndefined();
      expect(authnRequest["saml:Issuer"][0].$.NameQualifier).toEqual(
        samlConfigMock.issuer
      );
      expect(authnRequest["saml:Issuer"][0].$.Format).toEqual(ISSUER_FORMAT);
    }
  });

  it("should Tamper an AuthNRequest without overriding ID property if lollipopParams are undefined", async () => {
    const authRequestTamperer = getAuthorizeRequestTamperer(
      builder,
      samlConfigMock
    );
    const result = await authRequestTamperer(
      samlRequestWithID(aSamlRequestID)
    )();
    expect(E.isRight(result)).toBeTruthy();
    if (E.isRight(result)) {
      const parsedXml = await parseStringPromise(result.right);
      const authnRequest = parsedXml["samlp:AuthnRequest"];
      expect(authnRequest.$.ID).toEqual(aSamlRequestID);
      expect(
        authnRequest["samlp:NameIDPolicy"][0].$.AllowCreate
      ).toBeUndefined();
      expect(authnRequest["saml:Issuer"][0].$.NameQualifier).toEqual(
        samlConfigMock.issuer
      );
      expect(authnRequest["saml:Issuer"][0].$.Format).toEqual(ISSUER_FORMAT);
    }
  });

  it("should return an error if authNRequest XML is invalid", async () => {
    const authRequestTamperer = getAuthorizeRequestTamperer(
      builder,
      samlConfigMock
    );
    const result = await authRequestTamperer(fakeXml)();
    expect(E.isLeft(result)).toBeTruthy();
    if (E.isLeft(result)) {
      expect(result.left.name).toContain("TypeError");
    }
  });
});

describe("calculateJwkThumbprint", () => {
  it("should calculate the same thumbprint on same jwk with different properties order", async () => {
    const aJwkPubKeyThumbprint = await jose.calculateJwkThumbprint(aJwkPubKey);
    const sameJwkPubKeyWithDifferentPropertiesOrder: JwkPublicKey = {
      crv: "secp256k1",
      x: "Q8K81dZcC4DdKl52iW7bT0ubXXm2amN835M_v5AgpSE",
      y: "lLsw82Q414zPWPluI5BmdKHK6XbFfinc8aRqbZCEv0A",
      kty: "EC"
    };
    const sameJwkWithDifferentOrderThumbprint = await jose.calculateJwkThumbprint(
      sameJwkPubKeyWithDifferentPropertiesOrder
    );
    expect(aJwkPubKeyThumbprint).toEqual(sameJwkWithDifferentOrderThumbprint);
  });
});
