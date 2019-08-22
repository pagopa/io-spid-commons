"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const t = require("io-ts");
const strings_1 = require("italia-ts-commons/lib/strings");
//
const strings_2 = require("italia-ts-commons/lib/strings");
const strings_3 = require("italia-ts-commons/lib/strings");
const spidLevel_1 = require("./spidLevel");
const issuer_1 = require("./issuer");
exports.SpidUser = t.intersection([
    t.interface({
        authnContextClassRef: spidLevel_1.SpidLevel,
        getAssertionXml: t.Function,
        issuer: issuer_1.Issuer
    }),
    t.partial({
        email: strings_2.EmailString,
        familyName: t.string,
        fiscalNumber: strings_3.FiscalCode,
        mobilePhone: strings_1.NonEmptyString,
        name: t.string,
        nameID: t.string,
        nameIDFormat: t.string,
        sessionIndex: t.string
    })
]);
//# sourceMappingURL=spidUser.js.map