import { Option } from "fp-ts/lib/Option";
/**
 * Extract StatusMessage from SAML response
 *
 * ie. for <StatusMessage>ErrorCode nr22</StatusMessage>
 * returns "22"
 */
export declare function getErrorCodeFromResponse(xml: string): Option<string>;
