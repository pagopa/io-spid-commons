"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const t = require("io-ts");
const strings_1 = require("italia-ts-commons/lib/strings");
//
const EmailAddress_1 = require("../../generated/backend/EmailAddress");
const FiscalCode_1 = require("../../generated/backend/FiscalCode");
const SpidLevel_1 = require("../../generated/backend/SpidLevel");
const issuer_1 = require("./issuer");
exports.SpidUser = t.intersection([
    t.interface({
        authnContextClassRef: SpidLevel_1.SpidLevel,
        getAssertionXml: t.Function,
        issuer: issuer_1.Issuer
    }),
    t.partial({
        email: EmailAddress_1.EmailAddress,
        familyName: t.string,
        fiscalNumber: FiscalCode_1.FiscalCode,
        mobilePhone: strings_1.NonEmptyString,
        name: t.string,
        nameID: t.string,
        nameIDFormat: t.string,
        sessionIndex: t.string
    })
]);
//# sourceMappingURL=spidUser.js.map