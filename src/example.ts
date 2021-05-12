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
import {
  AggregatorType,
  ContactType,
  EntityType,
  IServiceProviderConfig
} from "./utils/middleware";

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
  sloPath: "/logout",
  spidLevelsWhitelist: ["SpidL2", "SpidL3"]
};

const serviceProviderConfig: IServiceProviderConfig = {
  IDPMetadataUrl:
    "https://registry.spid.gov.it/metadata/idp/spid-entities-idps.xml",
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
  spidCieUrl:
    "https://preproduzione.idserver.servizicie.interno.gov.it/idp/shibboleth?Metadata",
  spidTestEnvUrl: "https://spid-testenv2:8088",
  // this line is commented due to a future refactor that enables spid-saml-check locally
  // spidValidatorUrl: "http://localhost:8080",
  strictResponseValidation: {
    "http://localhost:8080": true,
    "https://spid-testenv2:8088": true
  },

  contacts: [
    {
      company: "Sogetto Aggregatore s.r.l",
      contactType: ContactType.OTHER,
      email: "email@example.com" as EmailString,
      entityType: EntityType.AGGREGATOR,
      extensions: {
        FiscalCode: "12345678901",
        IPACode: "1",
        VATNumber: "12345678902",
        aggregatorType: AggregatorType.PublicServicesFullOperator
      },
      phone: "+393331234567"
    }
  ]
};

const redisClient = redis.createClient({
  host: "redis"
});

const samlConfig: SamlConfig = {
  RACComparison: "minimum",
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

// Create a Proxy to forward local calls to spid validator container
const proxyApp = express();
proxyApp.get("*", (req, res) => {
  res.redirect("http://spid-saml-check:8080" + req.path);
});
proxyApp.listen(8080);

const doneCb = (ip: string | null, request: string, response: string) => {
  // tslint:disable-next-line: no-console
  console.log("*************** done", ip);
  // tslint:disable-next-line: no-console
  console.log(request);
  // tslint:disable-next-line: no-console
  console.log(response);
};

withSpid({
  acs,
  app,
  appConfig,
  doneCb,
  logout,
  redisClient,
  samlConfig,
  serviceProviderConfig
})
  .map(({ app: withSpidApp, idpMetadataRefresher }) => {
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
    withSpidApp.get("/refresh", async (_, res) => {
      await idpMetadataRefresher().run();
      res.json({
        metadataUpdate: "completed"
      });
    });
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
