import * as xmldom from "xmldom";

declare module "xmldom" {
  interface DOMParser {
    parseFromString(xmlsource: string, mimeType?: string): Document | undefined;
  }
}
