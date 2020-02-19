import * as bodyParser from "body-parser";
import * as express from "express";
import * as fs from "fs";
import * as t from "io-ts";
import { ResponsePermanentRedirect } from "italia-ts-commons/lib/responses";
import {
  EmailString,
  FiscalCode,
  NonEmptyString
} from "italia-ts-commons/lib/strings";
import passport = require("passport");
import { SamlConfig } from "passport-saml";
import * as redis from "redis";
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
    // the following values may be set
    // by the calling application:
    // authnContextClassRef: SpidLevel,
    // issuer: Issuer
    getAssertionXml: t.Function
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

const appConfig: IApplicationConfig = {
  assertionConsumerServicePath: "/acs",
  clientErrorRedirectionUrl: "/error",
  clientLoginRedirectionUrl: "/success",
  loginPath: "/login",
  metadataPath: "/metadata",
  sloPath: "/logout"
};

const serviceProviderConfig: IServiceProviderConfig = {
  IDPMetadataUrl:
    "https://registry.spid.gov.it/metadata/idp/spid-entities-idps.xml",
  idpMetadataRefreshIntervalMillis: 120000,
  organization: {
    URL: "https://example.com",
    displayName: "Organization display name",
    name: "Organization name"
  },
  publicCert: fs.readFileSync("./certs/cert.pem", "utf-8"),
  requiredAttributes: {
    attributes: [
      "address",
      "email",
      "name",
      "familyName",
      "fiscalNumber",
      "mobilePhone"
    ],
    name: "Required attrs"
  },
  spidTestEnvUrl: "https://spid-testenv2:8088",
  spidValidatorUrl: "http://localhost:8080"
};

const redisClient = redis.createClient({
  host: "redis"
});

const samlConfig: SamlConfig = {
  acceptedClockSkewMs: 0,
  attributeConsumingServiceIndex: "0",
  authnContext: "https://www.spid.gov.it/SpidL1",
  callbackUrl: "http://localhost:3000" + appConfig.assertionConsumerServicePath,
  // decryptionPvk: fs.readFileSync("./certs/key.pem", "utf-8"),
  identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
  issuer: "https://spid.agid.gov.it/cd",
  logoutCallbackUrl: "http://localhost:3000/slo",
  privateCert: fs.readFileSync("./certs/key.pem", "utf-8"),
  validateInResponseTo: true
};

const acs: AssertionConsumerServiceT = async payload => {
  logger.info("acs:%s", JSON.stringify(payload));
  return ResponsePermanentRedirect({ href: "/success?acs" });
};

const logout: LogoutT = async () =>
  ResponsePermanentRedirect({ href: "/success?logout" });

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(passport.initialize());

withSpid(
  appConfig,
  samlConfig,
  serviceProviderConfig,
  redisClient,
  app,
  acs,
  logout
)
  .map(({ app: withSpidApp, startIdpMetadataRefreshTimer }) => {
    const idpMetadataRefreshTimer = startIdpMetadataRefreshTimer();
    withSpidApp.on("server:stop", () => clearInterval(idpMetadataRefreshTimer));
    withSpidApp.get("/success", (_, res) =>
      res.json({
        success: "success"
      })
    );
    withSpidApp.get("/error", (_, res) =>
      res
        .json({
          error: "error"
        })
        .status(400)
    );
    withSpidApp.use(
      (
        error: Error,
        _: express.Request,
        res: express.Response,
        ___: express.NextFunction
      ) =>
        res.status(505).send({
          error: error.message
        })
    );
    withSpidApp.listen(3000);
  })
  .run()
  // tslint:disable-next-line: no-console
  .catch(e => console.error("Application error: ", e));
