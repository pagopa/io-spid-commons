"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const t = require("io-ts");
// tslint:disable-next-line: no-submodule-imports
const createNonEmptyArrayFromArray_1 = require("io-ts-types/lib/fp-ts/createNonEmptyArrayFromArray");
const strings_1 = require("italia-ts-commons/lib/strings");
exports.IDPEntityDescriptor = t.interface({
    cert: createNonEmptyArrayFromArray_1.createNonEmptyArrayFromArray(strings_1.NonEmptyString),
    entityID: t.string,
    entryPoint: t.string,
    logoutUrl: t.string
});
//# sourceMappingURL=IDPEntityDescriptor.js.map