/**
 * Methods to fetch and parse Identity service providers metadata.
 */
import { errorsToReadableMessages } from "@pagopa/ts-commons/lib/reporters";
import * as E from "fp-ts/lib/Either";
import { Either } from "fp-ts/lib/Either";
import { pipe } from "fp-ts/lib/function";
import * as R from "fp-ts/lib/Record";
import { Ord } from "fp-ts/lib/string";
import * as TE from "fp-ts/lib/TaskEither";
import { TaskEither } from "fp-ts/lib/TaskEither";
import nodeFetch from "node-fetch";
import { CIE_IDP_IDENTIFIERS, SPID_IDP_IDENTIFIERS } from "../config";
import { IDPEntityDescriptor } from "../types/IDPEntityDescriptor";
import { logger } from "./logger";
import { safeXMLParseFromString } from "./samlUtils";

const EntityDescriptorTAG = "EntityDescriptor";
const X509CertificateTAG = "X509Certificate";
const SingleSignOnServiceTAG = "SingleSignOnService";
const SingleLogoutServiceTAG = "SingleLogoutService";

const METADATA_NAMESPACES = {
  METADATA: "urn:oasis:names:tc:SAML:2.0:metadata",
  XMLDSIG: "http://www.w3.org/2000/09/xmldsig#",
};

/**
 * Parse a string that represents an XML file containing
 * the ipd Metadata and converts it into an array of IDPEntityDescriptor
 *
 * Required namespace definitions into the XML are
 *  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" and xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
 *
 * An example file is provided in /test_idps/spid-entities-idps.xml of this project.
 */
export const parseIdpMetadata = (
  idpMetadataPage: string
): Either<Error, ReadonlyArray<IDPEntityDescriptor>> =>
  pipe(
    safeXMLParseFromString(idpMetadataPage),
    E.fromOption(() => new Error("Empty XML file content")),
    E.chain(
      E.fromPredicate(
        (domParser) =>
          domParser && !domParser.getElementsByTagName("parsererror").item(0),
        () => new Error("XML parser error")
      )
    ),
    E.chain((domParser) => {
      const entityDescriptors = domParser.getElementsByTagNameNS(
        METADATA_NAMESPACES.METADATA,
        EntityDescriptorTAG
      );
      return E.right(
        Array.from(entityDescriptors).reduce(
          (idps: ReadonlyArray<IDPEntityDescriptor>, element: Element) => {
            const certs = Array.from(
              element.getElementsByTagNameNS(
                METADATA_NAMESPACES.XMLDSIG,
                X509CertificateTAG
              )
            ).map((_) =>
              _.textContent ? _.textContent.replace(/[\n\s]/g, "") : ""
            );
            return pipe(
              IDPEntityDescriptor.decode({
                cert: certs,
                entityID: element.getAttribute("entityID"),
                entryPoint: Array.from(
                  element.getElementsByTagNameNS(
                    METADATA_NAMESPACES.METADATA,
                    SingleSignOnServiceTAG
                  )
                )
                  .filter(
                    (_) =>
                      _.getAttribute("Binding") ===
                      "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                  )[0]
                  ?.getAttribute("Location"),
                logoutUrl:
                  Array.from(
                    element.getElementsByTagNameNS(
                      METADATA_NAMESPACES.METADATA,
                      SingleLogoutServiceTAG
                    )
                  )
                    .filter(
                      (_) =>
                        _.getAttribute("Binding") ===
                        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                    )[0]
                    // If SingleLogoutService is missing will be return an empty string
                    // Needed for CIE Metadata
                    ?.getAttribute("Location") || "",
              }),
              E.fold(
                (errs) => {
                  logger.warn(
                    "Invalid md:EntityDescriptor. %s",
                    errorsToReadableMessages(errs).join(" / ")
                  );
                  return idps;
                },
                (elementInfo) => [...idps, elementInfo]
              )
            );
          },
          []
        )
      );
    })
  );

/**
 * Map provided idpMetadata into an object with idp key whitelisted in ipdIds.
 * Mapping is based on entityID property
 */
export const mapIpdMetadata = (
  idpMetadata: ReadonlyArray<IDPEntityDescriptor>,
  idpIds: Record<string, string>
): Record<string, IDPEntityDescriptor> =>
  idpMetadata.reduce<Record<string, IDPEntityDescriptor>>((prev, idp) => {
    const idpKey = idpIds[idp.entityID];
    if (idpKey) {
      return { ...prev, [idpKey]: idp };
    }
    logger.warn(
      `Unsupported SPID idp from metadata repository [${idp.entityID}]`
    );
    return prev;
  }, {});

/**
 * Lazy version of mapIpdMetadata()
 */
export const mapIpdMetadataL =
  (idpIds: Record<string, string>) =>
  (
    idpMetadata: ReadonlyArray<IDPEntityDescriptor>
  ): Record<string, IDPEntityDescriptor> =>
    mapIpdMetadata(idpMetadata, idpIds);

/**
 * Fetch an XML from a remote URL
 */
export const fetchMetadataXML = (
  idpMetadataUrl: string
): TaskEither<Error, string> =>
  pipe(
    TE.tryCatch(() => {
      logger.info("Fetching SPID metadata from [%s]...", idpMetadataUrl);
      return nodeFetch(idpMetadataUrl);
    }, E.toError),
    TE.chain(
      TE.fromPredicate(
        (p) => p.status >= 200 && p.status < 300,
        () => {
          logger.warn("Error fetching remote metadata for %s", idpMetadataUrl);
          return new Error("Error fetching remote metadata");
        }
      )
    ),
    TE.chain((p) => TE.tryCatch(() => p.text(), E.toError))
  );

/**
 * Load idp Metadata from a remote url, parse infos and return a mapped and whitelisted idp options
 * for spidStrategy object.
 */
export const fetchIdpsMetadata = (
  idpMetadataUrl: string,
  idpIds: Record<string, string>
): TaskEither<Error, Record<string, IDPEntityDescriptor>> =>
  pipe(
    fetchMetadataXML(idpMetadataUrl),
    TE.chain((idpMetadataXML) => {
      logger.info("Parsing SPID metadata for %s", idpMetadataUrl);
      return TE.fromEither(parseIdpMetadata(idpMetadataXML));
    }),
    TE.chain(
      TE.fromPredicate(
        (idpMetadata) => idpMetadata.length > 0,
        () => {
          logger.error("No SPID metadata found for %s", idpMetadataUrl);
          return new Error("No SPID metadata found");
        }
      )
    ),
    TE.map((idpMetadata) => {
      if (!idpMetadata.length) {
        logger.warn("Missing SPID metadata on %s", idpMetadataUrl);
      }
      logger.info("Configuring IdPs for %s", idpMetadataUrl);
      return mapIpdMetadata(idpMetadata, idpIds);
    })
  );

/**
 * This method expects in input a Record where key are idp identifier
 * and values are an XML string (idp metadata).
 * Provided metadata are parsed and converted into IDP Entity Descriptor objects.
 */
export const parseStartupIdpsMetadata = (
  idpsMetadata: Record<string, string>
): Record<string, IDPEntityDescriptor> =>
  pipe(
    idpsMetadata,
    R.reduce(Ord)(
      [] as ReadonlyArray<IDPEntityDescriptor>,
      (prev, metadataXML) => [
        ...prev,
        ...pipe(
          parseIdpMetadata(metadataXML),
          E.getOrElseW(() => [])
        ),
      ]
    ),
    mapIpdMetadataL({ ...SPID_IDP_IDENTIFIERS, ...CIE_IDP_IDENTIFIERS })
  );
