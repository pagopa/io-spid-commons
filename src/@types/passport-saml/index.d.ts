import {
  SamlConfig,
  VerifyWithRequest,
  VerifyWithoutRequest
} from "passport-saml";

declare class SamlClient {
  constructor(
    config: SamlConfig,
    verify: VerifyWithRequest | VerifyWithoutRequest
  );
}
