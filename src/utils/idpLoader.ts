import { Either, right, toError, tryCatch2v } from "fp-ts/lib/Either";
import {
  fromEither,
  fromPredicate,
  TaskEither,
  tryCatch
} from "fp-ts/lib/TaskEither";
import { errorsToReadableMessages } from "italia-ts-commons/lib/reporters";
import nodeFetch from "node-fetch";
import { DOMParser } from "xmldom";
import { IDPEntityDescriptor } from "../types/IDPEntityDescriptor";
import { logger } from "./logger";

const EntityDescriptorTAG = "md:EntityDescriptor";
const X509CertificateTAG = "ds:X509Certificate";
const SingleSignOnServiceTAG = "md:SingleSignOnService";
const SingleLogoutServiceTAG = "md:SingleLogoutService";

/**
 * Parse a string that represents an XML file containing
 * the ipd Metadata and converts it into an array of IDPEntityDescriptor
 *
 * Required namespace definitions into the XML are
 *  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" and xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
 *
 * An example file is provided in /test_idps/spid-entities-idps.xml of this project.
 */
export function parseIdpMetadata(
  ipdMetadataPage: string
): Either<Error, ReadonlyArray<IDPEntityDescriptor>> {
  return tryCatch2v(
    () => new DOMParser().parseFromString(ipdMetadataPage),
    err => {
      logger.error("parseIdpMetadata() | %s", err);
      return toError(err);
    }
  ).chain(domParser => {
    const entityDescriptors = domParser.getElementsByTagName(
      EntityDescriptorTAG
    );
    return right(
      Array.from(entityDescriptors).reduce(
        (idps: ReadonlyArray<IDPEntityDescriptor>, element: Element) => {
          const certs = Array.from(
            element.getElementsByTagName(X509CertificateTAG)
          ).map(_ =>
            _.textContent ? _.textContent.replace(/[\n\s]/g, "") : ""
          );
          try {
            return IDPEntityDescriptor.decode({
              cert: certs,
              entityID: element.getAttribute("entityID"),
              entryPoint: Array.from(
                element.getElementsByTagName(SingleSignOnServiceTAG)
              )
                .filter(
                  _ =>
                    _.getAttribute("Binding") ===
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                )[0]
                .getAttribute("Location"),
              logoutUrl: Array.from(
                element.getElementsByTagName(SingleLogoutServiceTAG)
              )
                .filter(
                  _ =>
                    _.getAttribute("Binding") ===
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                )[0]
                .getAttribute("Location")
            }).fold(
              errs => {
                logger.warn(
                  "Invalid md:EntityDescriptor. %s",
                  errorsToReadableMessages(errs).join(" / ")
                );
                return idps;
              },
              elementInfo => [...idps, elementInfo]
            );
          } catch {
            logger.warn(
              "Invalid md:EntityDescriptor. %s",
              new Error("Unable to parse element info")
            );
            return idps;
          }
        },
        []
      )
    );
  });
}

/**
 * Map provided idpMetadata into an object with idp key whitelisted in ipdIds.
 * Mapping is based on entityID property
 */
export const mapIpdMetadata = (
  idpMetadata: ReadonlyArray<IDPEntityDescriptor>,
  idpIds: Record<string, string>
) =>
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
 * Load idp Metadata from a remote url, parse infos and return a mapped and whitelisted idp options
 * for spidStrategy object.
 */
export function fetchIdpsMetadata(
  idpMetadataUrl: string,
  idpIds: Record<string, string>
): TaskEither<Error, Record<string, IDPEntityDescriptor>> {
  return tryCatch(() => {
    logger.info("Fetching SPID metadata from [%s]...", idpMetadataUrl);
    return nodeFetch(idpMetadataUrl);
  }, toError)
    .chain(p => tryCatch(() => p.text(), toError))
    .chain(idpMetadataXML => {
      logger.info("Parsing SPID metadata...");
      return fromEither(parseIdpMetadata(idpMetadataXML));
    })
    .chain(
      fromPredicate(
        idpMetadata => idpMetadata.length > 0,
        () => {
          logger.error(
            "No SPID metadata found from the url: %s",
            idpMetadataUrl
          );
          return new Error("No SPID metadata found");
        }
      )
    )
    .map(idpMetadata => {
      if (idpMetadata.length < Object.keys(idpIds).length) {
        logger.warn("Missing SPID metadata on [%s]", idpMetadataUrl);
      }
      logger.info("Configuring IdPs...");
      return mapIpdMetadata(idpMetadata, idpIds);
    });
}
