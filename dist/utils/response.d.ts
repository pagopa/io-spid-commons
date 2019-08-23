import { Option } from "fp-ts/lib/Option";
/**
 * Extract StatusMessage from SAML response
 *
 * ie. for <StatusMessage>ErrorCode nr22</StatusMessage>
 * returns "22"
 */
export declare function getErrorCodeFromResponse(xml: string): Option<string>;
/**
 * Extract AuthnContextClassRef from SAML response
 *
 * ie. for <saml2:AuthnContextClassRef>https://www.spid.gov.it/SpidL2</saml2:AuthnContextClassRef>
 * returns "https://www.spid.gov.it/SpidL2"
 */
export declare function getAuthnContextFromResponse(xml: string): Option<string>;
