"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const logform = require("logform");
const winston_1 = require("winston");
const { timestamp, printf } = logform.format;
exports.log = winston_1.createLogger({
    format: winston_1.format.combine(timestamp(), winston_1.format.splat(), winston_1.format.simple(), printf(nfo => {
        return `${nfo.timestamp} [${nfo.level}]: ${nfo.message}`;
    })),
    transports: [new winston_1.transports.Console()]
});
//# sourceMappingURL=logger.js.map