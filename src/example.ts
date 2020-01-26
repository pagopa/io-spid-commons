import {
  EmailString,
  FiscalCode,
  NonEmptyString
} from "italia-ts-commons/lib/strings";

import * as bodyParser from "body-parser";
import * as express from "express";
import * as fs from "fs";
import * as t from "io-ts";
import { ResponsePermanentRedirect } from "italia-ts-commons/lib/responses";
import passport = require("passport");
import { SamlConfig } from "passport-saml";
import {
  AssertionConsumerServiceT,
  IApplicationConfig,
  LogoutT,
  withSpid
} from ".";
import { logger } from "./utils/logger";
import { IServiceProviderConfig } from "./utils/middleware";

export const SpidUser = t.intersection([
  t.interface({
    // authnContextClassRef: SpidLevel,
    getAssertionXml: t.Function
    // issuer: Issuer
  }),
  t.partial({
    email: EmailString,
    familyName: t.string,
    fiscalNumber: FiscalCode,
    mobilePhone: NonEmptyString,
    name: t.string,
    nameID: t.string,
    nameIDFormat: t.string,
    sessionIndex: t.string
  })
]);

export type SpidUser = t.TypeOf<typeof SpidUser>;

const appConfigL: IApplicationConfig = {
  assertionConsumerServicePath: "/acs",
  clientErrorRedirectionUrl: "/ko",
  clientLoginRedirectionUrl: "/ok",
  loginPath: "/login",
  metadataPath: "/metadata.xml",
  sloPath: "/logout"
};

const serviceProviderConfigL: IServiceProviderConfig = {
  IDPMetadataUrl:
    "https://registry.spid.gov.it/metadata/idp/spid-entities-idps.xml",
  hasSpidValidatorEnabled: true,
  organization: {
    URL: "https://example.com",
    displayName: "Organization display name",
    name: "Organization name"
  },
  publicCert: fs.readFileSync("./certs/cert.pem", "utf-8"),
  requiredAttributes: {
    attributes: ["email", "name", "familyName", "fiscalNumber", "mobilePhone"],
    name: "Required attrs"
  },
  spidTestEnvUrl: "https://spid-testenv2:8088"
};

const samlConfigL: SamlConfig = {
  acceptedClockSkewMs: 0,
  attributeConsumingServiceIndex: "0",
  authnContext: "https://www.spid.gov.it/SpidL1",
  callbackUrl: "http://localhost:3000/acs",
  // decryptionPvk: fs.readFileSync("./certs/key.pem", "utf-8"),
  identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
  issuer: "https://spid.agid.gov.it/cd",
  logoutCallbackUrl: "http://localhost:3000/slo",
  privateCert: fs.readFileSync("./certs/key.pem", "utf-8")
};

const acs: AssertionConsumerServiceT = async payload => {
  logger.info("acs:%s", JSON.stringify(payload));
  return ResponsePermanentRedirect({ href: "/ok?user=" });
};

const logout: LogoutT = async () =>
  ResponsePermanentRedirect({ href: "/ok?logout" });

const appL = express();

appL.use(bodyParser.json());
appL.use(bodyParser.urlencoded({ extended: true }));
appL.use(passport.initialize());

withSpid(appConfigL, samlConfigL, serviceProviderConfigL, appL, acs, logout)
  .map(app => {
    app.get("/ok", (_, res) => res.json({ ok: "ok" }));
    app.get("/ko", (_, res) => res.json({ ok: "ko" }));
    app.use(
      (
        error: Error,
        _: express.Request,
        res: express.Response,
        ___: express.NextFunction
      ) => res.status(505).send({ error: error.message })
    );
    app.listen(3000);
  })
  .run()
  // tslint:disable-next-line: no-console
  .catch(e => console.error("caught error: ", e));
