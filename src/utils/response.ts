import { DOMParser } from "@xmldom/xmldom";

import { ResponseErrorInternal } from "@pagopa/ts-commons/lib/responses";
import { NextFunction, Request, Response } from "express";
import { pipe } from "fp-ts/lib/function";
import * as O from "fp-ts/lib/Option";
import { Option } from "fp-ts/lib/Option";
import { SAML_NAMESPACE } from "./saml";

/**
 * Extract AuthnContextClassRef from SAML response.
 *
 * ie. for <saml2:AuthnContextClassRef>https://www.spid.gov.it/SpidL2</saml2:AuthnContextClassRef>
 * returns "https://www.spid.gov.it/SpidL2"
 */
export const getAuthnContextFromResponse = (xml: string): Option<string> =>
  pipe(
    O.fromNullable(xml),
    O.chain((xmlStr) =>
      O.tryCatch(() => new DOMParser().parseFromString(xmlStr))
    ),
    O.chain((xmlResponse) =>
      xmlResponse
        ? O.some(
            xmlResponse.getElementsByTagNameNS(
              SAML_NAMESPACE.ASSERTION,
              "AuthnContextClassRef"
            )
          )
        : O.none
    ),
    O.chain((responseAuthLevelEl) =>
      responseAuthLevelEl?.[0]?.textContent
        ? O.some(responseAuthLevelEl[0].textContent.trim())
        : O.none
    )
  );

export const middlewareCatchAsInternalError =
  (
    f: (req: Request, res: Response, next: NextFunction) => unknown,
    message: string = "Exception while calling express middleware"
  ) =>
  (req: Request, res: Response, next: NextFunction): void => {
    try {
      f(req, res, next);
    } catch (_) {
      // Send a ResponseErrorInternal only if a response was not already sent to the client
      if (!res.headersSent) {
        return ResponseErrorInternal(`${message} [${_}]`).apply(res);
      }
    }
  };
