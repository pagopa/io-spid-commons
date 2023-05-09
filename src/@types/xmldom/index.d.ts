// Type definitions for xmldom 0.1.22
// Project: https://github.com/xmldom/xmldom
// Definitions by: Qubo <https://github.com/tkqubo>
//                 Karfau <https://github.com/karfau>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped
/// <reference lib="dom" />

import * as xmldom from "xmldom";

declare module "xmldom" {
  interface DOMParser {
    parseFromString(xmlsource: string, mimeType?: string): Document | undefined;
  }
}
