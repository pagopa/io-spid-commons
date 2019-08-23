"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const xmldom_1 = require("xmldom");
const Option_1 = require("fp-ts/lib/Option");
/**
 * Extract StatusMessage from SAML response
 *
 * ie. for <StatusMessage>ErrorCode nr22</StatusMessage>
 * returns "22"
 */
function getErrorCodeFromResponse(xml) {
    return Option_1.tryCatch(() => new xmldom_1.DOMParser().parseFromString(xml))
        .chain(xmlResponse => xmlResponse
        ? Option_1.some(xmlResponse.getElementsByTagName("StatusMessage"))
        : Option_1.none)
        .chain(responseStatusMessageEl => {
        return responseStatusMessageEl &&
            responseStatusMessageEl[0] &&
            responseStatusMessageEl[0].textContent
            ? Option_1.some(responseStatusMessageEl[0].textContent.trim())
            : Option_1.none;
    })
        .chain(errorString => {
        const indexString = "ErrorCode nr";
        const errorCode = errorString.slice(errorString.indexOf(indexString) + indexString.length);
        return errorCode ? Option_1.some(errorCode) : Option_1.none;
    });
}
exports.getErrorCodeFromResponse = getErrorCodeFromResponse;
/**
 * Extract AuthnContextClassRef from SAML response
 *
 * ie. for <saml2:AuthnContextClassRef>https://www.spid.gov.it/SpidL2</saml2:AuthnContextClassRef>
 * returns "https://www.spid.gov.it/SpidL2"
 */
function getAuthnContextFromResponse(xml) {
    return Option_1.fromNullable(xml)
        .chain(xmlStr => Option_1.tryCatch(() => new xmldom_1.DOMParser().parseFromString(xmlStr)))
        .chain(xmlResponse => xmlResponse
        ? Option_1.some(xmlResponse.getElementsByTagName("saml:AuthnContextClassRef"))
        : Option_1.none)
        .chain(responseAuthLevelEl => responseAuthLevelEl &&
        responseAuthLevelEl[0] &&
        responseAuthLevelEl[0].textContent
        ? Option_1.some(responseAuthLevelEl[0].textContent.trim())
        : Option_1.none);
}
exports.getAuthnContextFromResponse = getAuthnContextFromResponse;
//# sourceMappingURL=response.js.map