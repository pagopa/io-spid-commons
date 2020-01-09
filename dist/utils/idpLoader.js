"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const reporters_1 = require("italia-ts-commons/lib/reporters");
const node_fetch_1 = require("node-fetch");
const xmldom_1 = require("xmldom");
const IDPEntityDescriptor_1 = require("../types/IDPEntityDescriptor");
const logger_1 = require("./logger");
const EntityDescriptorTAG = "md:EntityDescriptor";
const X509CertificateTAG = "ds:X509Certificate";
const SingleSignOnServiceTAG = "md:SingleSignOnService";
const SingleLogoutServiceTAG = "md:SingleLogoutService";
/**
 * Parse a string that represents an XML file containing the ipd Metadata and converts it into an array of IDPEntityDescriptor
 * Required namespace definitions into the XML are xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" and xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
 * An example file is provided in /test_idps/spid-entities-idps.xml of this project.
 */
function parseIdpMetadata(ipdMetadataPage) {
    const domParser = new xmldom_1.DOMParser().parseFromString(ipdMetadataPage);
    if (!domParser) {
        logger_1.log.error(Error("Parsing of XML string containing IdP metadata failed"));
        return [];
    }
    const entityDescriptors = domParser.getElementsByTagName(EntityDescriptorTAG);
    return Array.from(entityDescriptors).reduce((idps, element) => {
        const certs = Array.from(element.getElementsByTagName(X509CertificateTAG)).map(_ => {
            if (_.textContent) {
                return _.textContent.replace(/[\n\s]/g, "");
            }
            return "";
        });
        try {
            const elementInfoOrErrors = IDPEntityDescriptor_1.IDPEntityDescriptor.decode({
                cert: certs,
                entityID: element.getAttribute("entityID"),
                entryPoint: Array.from(element.getElementsByTagName(SingleSignOnServiceTAG))
                    .filter(_ => _.getAttribute("Binding") ===
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")[0]
                    .getAttribute("Location"),
                logoutUrl: Array.from(element.getElementsByTagName(SingleLogoutServiceTAG))
                    .filter(_ => _.getAttribute("Binding") ===
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")[0]
                    .getAttribute("Location")
            });
            if (elementInfoOrErrors.isLeft()) {
                logger_1.log.warn("Invalid md:EntityDescriptor. %s", reporters_1.errorsToReadableMessages(elementInfoOrErrors.value).join(" / "));
                return idps;
            }
            return [...idps, elementInfoOrErrors.value];
        }
        catch (_a) {
            logger_1.log.warn("Invalid md:EntityDescriptor. %s", new Error("Unable to parse element info"));
            return idps;
        }
    }, []);
}
exports.parseIdpMetadata = parseIdpMetadata;
/**
 * Fetch an ipds Metadata XML file from a remote url and convert it into a string
 */
async function fetchIdpMetadata(idpMetadataUrl) {
    const idpMetadataRequest = await node_fetch_1.default(idpMetadataUrl);
    return await idpMetadataRequest.text();
}
exports.fetchIdpMetadata = fetchIdpMetadata;
/**
 * Map provided idpMetadata in an object with idp key whitelisted in ipdIds.
 * Mapping is based on entityID property
 */
exports.mapIpdMetadata = (idpMetadata, idpIds) => idpMetadata.reduce((prev, idp) => {
    const idpKey = idpIds[idp.entityID];
    const idpOption = Object.assign({}, idp, { cert: idp.cert.toArray() });
    if (idpKey) {
        return Object.assign({}, prev, { [idpKey]: idpOption });
    }
    logger_1.log.warn(`Unsupported SPID idp from metadata repository [${idp.entityID}]`);
    return prev;
}, {});
//# sourceMappingURL=idpLoader.js.map