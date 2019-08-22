"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.matchRoute = (path, method
// tslint:disable-next-line: no-any
) => {
    // tslint:disable-next-line: no-any
    return (r) => r.route &&
        r.route.path === path &&
        r.route.methods &&
        r.route.methods[method];
};
//# sourceMappingURL=express.js.map