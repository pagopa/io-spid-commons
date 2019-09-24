"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const Option_1 = require("fp-ts/lib/Option");
const t = require("io-ts");
const xmldom_1 = require("xmldom");
const SAMLResponse = t.type({
    SAMLResponse: t.string
});
exports.getSamlIssuer = (body) => {
    return Option_1.fromEither(SAMLResponse.decode(body))
        .map(_ => Buffer.from(_.SAMLResponse, "base64").toString("utf8"))
        .chain(_ => Option_1.fromNullable(new xmldom_1.DOMParser().parseFromString(_)))
        .chain(_ => Option_1.fromNullable(_.getElementsByTagName("saml:Issuer").item(0)))
        .chain(_ => Option_1.fromNullable(_.textContent))
        .getOrElse("UNKNOWN");
};
//# sourceMappingURL=saml.js.map