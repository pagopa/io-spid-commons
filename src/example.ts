import * as fs from "fs";
import { ResponsePermanentRedirect } from "@pagopa/ts-commons/lib/responses";
import {
  EmailString,
  FiscalCode,
  NonEmptyString
} from "@pagopa/ts-commons/lib/strings";
import * as bodyParser from "body-parser";
import * as express from "express";
import { pipe } from "fp-ts/lib/function";
import * as T from "fp-ts/lib/Task";
import * as t from "io-ts";
import passport = require("passport");
import { SamlConfig } from "passport-saml";
import * as redis from "redis";
import { ValidUrl } from "@pagopa/ts-commons/lib/url";
import { logger } from "./utils/logger";
import {
  AggregatorType,
  ContactType,
  EntityType,
  IServiceProviderConfig
} from "./utils/middleware";
import {
  AssertionConsumerServiceT,
  IApplicationConfig,
  LogoutT,
  withSpid
} from ".";

export const SpidUser = t.intersection([
  t.interface({
    // the following values may be set
    // by the calling application:
    // authnContextClassRef -> SpidLevel,
    // issuer -> Issuer
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
  spidCieTestUrl:
    "https://collaudo.idserver.servizicie.interno.gov.it/idp/shibboleth",
  spidCieUrl:
    "https://preproduzione.idserver.servizicie.interno.gov.it/idp/shibboleth?Metadata",
  spidTestEnvUrl: "https://spid-testenv2:8088",
  // this line is commented due to a future refactor that enables spid-saml-check locally
  // spidValidatorUrl: "http://localhost:8080",
  strictResponseValidation: {
    // eslint-disable-next-line @typescript-eslint/naming-convention
    "http://localhost:8080": true,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    "https://spid-testenv2:8088": true
  },

  // eslint-disable-next-line sort-keys
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
  return ResponsePermanentRedirect({ href: "/success?acs" } as ValidUrl);
};

const logout: LogoutT = async () =>
  ResponsePermanentRedirect({ href: "/success?logout" } as ValidUrl);

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(passport.initialize());

// Create a Proxy to forward local calls to spid validator container
const proxyApp = express();
proxyApp.get("*", (req, res) => {
  res.redirect(`http://spid-saml-check:8080${req.path}`);
});
proxyApp.listen(8080);

// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
const doneCb = (ip: string | null, request: string, response: string) => {
  // eslint-disable-next-line no-console
  console.log("*************** done", ip);
  // eslint-disable-next-line no-console
  console.log(request);
  // eslint-disable-next-line no-console
  console.log(response);
};

pipe(
  withSpid({
    acs,
    app,
    appConfig,
    doneCb,
    logout,
    redisClient,
    samlConfig,
    serviceProviderConfig
  }),
  T.map(({ app: withSpidApp, idpMetadataRefresher }) => {
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
      await idpMetadataRefresher()();
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
)()
  // eslint-disable-next-line no-console
  .catch(e => console.error("Application error: ", e));
