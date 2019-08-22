"use strict";
/**
 * SPID authentication level enum and types.
 *
 * @see http://www.agid.gov.it/agenda-digitale/infrastrutture-architetture/spid/percorso-attuazione
 */
Object.defineProperty(exports, "__esModule", { value: true });
const types_1 = require("italia-ts-commons/lib/types");
// tslint:disable: no-duplicate-string
var SpidLevelEnum;
(function (SpidLevelEnum) {
    SpidLevelEnum["https://www.spid.gov.it/SpidL1"] = "https://www.spid.gov.it/SpidL1";
    SpidLevelEnum["https://www.spid.gov.it/SpidL2"] = "https://www.spid.gov.it/SpidL2";
    SpidLevelEnum["https://www.spid.gov.it/SpidL3"] = "https://www.spid.gov.it/SpidL3";
})(SpidLevelEnum = exports.SpidLevelEnum || (exports.SpidLevelEnum = {}));
exports.SpidLevel = types_1.enumType(SpidLevelEnum, "SpidLevel");
function isSpidL1(uri) {
    return uri === SpidLevelEnum["https://www.spid.gov.it/SpidL1"];
}
function isSpidL2(uri) {
    return uri === SpidLevelEnum["https://www.spid.gov.it/SpidL2"];
}
function isSpidL3(uri) {
    return uri === SpidLevelEnum["https://www.spid.gov.it/SpidL3"];
}
function isSpidL(uri) {
    return isSpidL1(uri) || isSpidL2(uri) || isSpidL3(uri);
}
exports.isSpidL = isSpidL;
//# sourceMappingURL=spidLevel.js.map