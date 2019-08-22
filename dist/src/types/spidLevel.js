"use strict";
/**
 * SPID authentication level enum and types.
 *
 * @see http://www.agid.gov.it/agenda-digitale/infrastrutture-architetture/spid/percorso-attuazione
 */
Object.defineProperty(exports, "__esModule", { value: true });
const SpidLevel_1 = require("../../generated/backend/SpidLevel");
function isSpidL1(uri) {
    return uri === SpidLevel_1.SpidLevelEnum["https://www.spid.gov.it/SpidL1"];
}
function isSpidL2(uri) {
    return uri === SpidLevel_1.SpidLevelEnum["https://www.spid.gov.it/SpidL2"];
}
function isSpidL3(uri) {
    return uri === SpidLevel_1.SpidLevelEnum["https://www.spid.gov.it/SpidL3"];
}
function isSpidL(uri) {
    return isSpidL1(uri) || isSpidL2(uri) || isSpidL3(uri);
}
exports.isSpidL = isSpidL;
//# sourceMappingURL=spidLevel.js.map