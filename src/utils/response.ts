import { DOMParser } from "xmldom";

import { fromNullable, none, Option, some, tryCatch } from "fp-ts/lib/Option";
import { SAML_NAMESPACE } from "./saml";

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
        ? some(
            xmlResponse.getElementsByTagNameNS(
              SAML_NAMESPACE.ASSERTION,
              "AuthnContextClassRef"
            )
          )
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
