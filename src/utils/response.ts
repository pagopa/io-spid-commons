import { DOMParser } from "xmldom";

import { fromNullable, none, Option, some, tryCatch } from "fp-ts/lib/Option";

/**
 * Extract StatusMessage from SAML response
 *
 * ie. for <StatusMessage>ErrorCode nr22</StatusMessage>
 * returns "22"
 */
export function getErrorCodeFromResponse(xml: string): Option<string> {
  return tryCatch(() => new DOMParser().parseFromString(xml))
    .chain(xmlResponse =>
      xmlResponse
        ? some(xmlResponse.getElementsByTagName("StatusMessage"))
        : none
    )
    .chain(responseStatusMessageEl => {
      return responseStatusMessageEl &&
        responseStatusMessageEl[0] &&
        responseStatusMessageEl[0].textContent
        ? some(responseStatusMessageEl[0].textContent.trim())
        : none;
    })
    .chain(errorString => {
      const indexString = "ErrorCode nr";
      const errorCode = errorString.slice(
        errorString.indexOf(indexString) + indexString.length
      );
      return errorCode ? some(errorCode) : none;
    });
}

/**
 * Extract AuthnContextClassRef from SAML response
 *
 * ie. for <saml2:AuthnContextClassRef>https://www.spid.gov.it/SpidL2</saml2:AuthnContextClassRef>
 * returns "https://www.spid.gov.it/SpidL2"
 */
export function getAuthnContextFromResponse(xml: string): Option<string> {
  return fromNullable(xml)
    .chain(xmlStr => tryCatch(() => new DOMParser().parseFromString(xmlStr)))
    .chain(xmlResponse =>
      xmlResponse
        ? some(xmlResponse.getElementsByTagName("saml:AuthnContextClassRef"))
        : none
    )
    .chain(responseAuthLevelEl =>
      responseAuthLevelEl &&
      responseAuthLevelEl[0] &&
      responseAuthLevelEl[0].textContent
        ? some(responseAuthLevelEl[0].textContent.trim())
        : none
    );
}
