import * as express from "express";
import { SPID_RELOAD_ERROR, SpidPassport } from "../index";
import { ISpidStrategyConfig } from "../strategies/spidStrategy";
import * as spid from "../strategies/spidStrategy";
import { matchRoute } from "../utils/express";

// saml configuration vars
const samlCert = `
-----BEGIN CERTIFICATE-----
MIIDczCCAlqgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBTMQswCQYDVQQGEwJpdDEN
MAsGA1UECAwEUm9tZTEUMBIGA1UECgwLYWdpZC5nb3YuaXQxHzAdBgNVBAMMFmh0
dHBzOi8vaXRhbGlhLWJhY2tlbmQwHhcNMTcxMDI2MTAzNTQwWhcNMTgxMDI2MTAz
NTQwWjBTMQswCQYDVQQGEwJpdDENMAsGA1UECAwEUm9tZTEUMBIGA1UECgwLYWdp
ZC5nb3YuaXQxHzAdBgNVBAMMFmh0dHBzOi8vaXRhbGlhLWJhY2tlbmQwggEjMA0G
CSqGSIb3DQEBAQUAA4IBEAAwggELAoIBAgCXozdOvdlQhX2zyOvnpZJZWyhjmiRq
kBW7jkZHcmFRceeoVkXGn4bAFGGcqESFMVmaigTEm1c6gJpRojo75smqyWxngEk1
XLctn1+Qhb5SCbd2oHh0oLE5jpHyrxfxw8V+N2Hty26GavJE7i9jORbjeQCMkbgg
t0FahmlmaZr20akK8wNGMHDcpnMslJPxHl6uKxjAfe6sbNqjWxfcnirm05Jh5gYN
T4vkwC1vx6AZpS2G9pxOV1q5GapuvUBqwNu+EH1ufMRRXvu0+GtJ4WtsErOakSF4
KMezrMqKCrVPoK5SGxQMD/kwEQ8HfUPpim3cdi3RVmqQjsi/on6DMn/xTQIDAQAB
o1AwTjAdBgNVHQ4EFgQULOauBsRgsAudzlxzwEXYXd4uPyIwHwYDVR0jBBgwFoAU
LOauBsRgsAudzlxzwEXYXd4uPyIwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0F
AAOCAQIAQOT5nIiAefn8FAWiVYu2uEsHpxUQ/lKWn1Trnj7MyQW3QA/jNaJHL/Ep
szJ5GONOE0lVEG1on35kQOWR7qFWYhH9Llb8EAAAb5tbnCiA+WIx4wjRTE3CNLul
L8MoscacIc/rqWf5WygZQcPDX1yVxmK4F3YGG2qDTD3fr4wPweYHxn95JidTwzW8
Jv46ajSBvFJ95CoCYL3BUHaxPIlYkGbJFjQhuoxo2XM4iT6KFD4IGmdssS4NFgW+
OM+P8UsrYi2KZuyzSrHq5c0GJz0UzSs8cIDC/CPEajx2Uy+7TABwR4d20Hyo6WIm
IFJiDanROwzoG0YNd8aCWE8ZM2y81Ww=
-----END CERTIFICATE-----
`;
const samlKey = `
-----BEGIN PRIVATE KEY-----
MIIEwQIBADANBgkqhkiG9w0BAQEFAASCBKswggSnAgEAAoIBAgCXozdOvdlQhX2z
yOvnpZJZWyhjmiRqkBW7jkZHcmFRceeoVkXGn4bAFGGcqESFMVmaigTEm1c6gJpR
ojo75smqyWxngEk1XLctn1+Qhb5SCbd2oHh0oLE5jpHyrxfxw8V+N2Hty26GavJE
7i9jORbjeQCMkbggt0FahmlmaZr20akK8wNGMHDcpnMslJPxHl6uKxjAfe6sbNqj
Wxfcnirm05Jh5gYNT4vkwC1vx6AZpS2G9pxOV1q5GapuvUBqwNu+EH1ufMRRXvu0
+GtJ4WtsErOakSF4KMezrMqKCrVPoK5SGxQMD/kwEQ8HfUPpim3cdi3RVmqQjsi/
on6DMn/xTQIDAQABAoIBAWo61Yw8Q/m9CwrgPyPRQm2HBwx/9/MPbaovSdzTrIm6
Gmg7yDYVm/kETj3JQ/drUzKIbj6t9LXvUizOUa2VSMJ0yZTYsnDHuywi8nf0uhgO
5pAca0aJLJ792hEByOx+EeUSN3C3i35vfbn8gwYoAHjrVA8mJrAEsawRbdVpNj6j
IWAKTmsZK0YLdcNzWshSYW9wkJNykeXHUgKk2YzGUIacMgC+fF3v3xL82xk+eLez
dP5wlrzkPz8JKHMIomF5j/VLuggSZx0XdQRvZrkeQUbJqRy2iXa43B+OlEiNvd2Q
0AiXur/MhvID+Ni/hBIoeIDyvvoBoiCTZbVvyRnBds8BAoGBDIfqHTTcfXlzfipt
4+idRuuzzhIXzQOcB0+8ywqmgtE4g9EykC7fEcynOavv08rOSNSbYhjLX24xUSrd
19lckZIvH5U9nJxnyfwrMGrorCA2uPtck8N9sTB5UWif31w/eDVMv30jRUyMel7l
tp96zxcPThT1O3N4zM2Otk5q2DvFAoGBDBngF4G9dJ5a511dyYco2agMJTvJLIqn
kKw24KOTqZ5BZKyIea4yCy9cRmNN84ccOy3jBuzSFLNJMYqdDCzH46u0I4anft83
aqnVa4jOwjZXoV9JCdFh3zKJUgPU4CW0MaTb30n3U4BAOgkHzRFt55tGT6xRU1J+
jX5s03BFfQ/pAoGBCsRqtUfrweEvDRT2MeR56Cu153cCfoYAdwPcDHeNVlDih9mk
4eF0ib3ZXyPPQqQ8FrahAWyeq9Rqif0UfFloQiljVncNZtm6EQQeNE9YuDZB7zcF
eG59PViSlhIZdXq1itv5o3yqZux8tNV/+ykUBIgi/YvioH/7J7flTd8Zzc2lAoGB
CqdVNRzSETPBUGRQx7Yo7scWOkmSaZaAw8v6XHdm7zQW2m1Tkd0czeAaWxXecQKI
hkl10Ij6w6K8U9N3RFrAeN6YL5bDK92VSmDPNmcxsKZrK/VZtj0S74/sebpJ1jUb
mYFM2h6ikm8dHHsK1S39FqULl+VbjAHazPN7GAOGCf7RAoGBAc0J9j+MHYm4M18K
AW2UB26qvdc8PSXE6i4YQAsg2RBgtf6u4jVAQ8a8OA4vnGG9VIrR0bD/hFTfczg/
ZbWGZ+42VH2eDGouiadR4rWzJNQKjWd98Y5PzxdEjd6nneJ68iNqGbKOT6jXu8qj
nCnxP/vK5rgVHU3nQfq+e/B6FVWZ
-----END PRIVATE KEY-----
`;
const samlCallbackUrl = "http://italia-backend/assertionConsumerService";
const samlIssuer = "https://spid.agid.gov.it/cd";
const samlAcceptedClockSkewMs = -1;
const samlAttributeConsumingServiceIndex = 0;
const spidAutologin = "";
const spidTestEnvUrl = "https://localhost:8088";
const IDPMetadataUrl =
  "https://raw.githubusercontent.com/teamdigitale/io-backend/164984224-download-idp-metadata/test_idps/spid-entities-idps.xml";

const expectedLoginPath = "/login";
const spidStrategyConfig: ISpidStrategyConfig = {
  samlKey,
  // tslint:disable-next-line: object-literal-sort-keys
  samlCert,
  samlCallbackUrl,
  samlIssuer,
  samlAcceptedClockSkewMs,
  samlAttributeConsumingServiceIndex,
  spidAutologin,
  spidTestEnvUrl,
  IDPMetadataUrl
};

describe("index", () => {
  // tslint:disable-next-line: no-let
  let app: express.Express | undefined;
  beforeEach(done => {
    // Create new Express app
    app = express();
    done();
  });
  it("Class contructor", done => {
    if (app === undefined) {
      return done(new Error("App not initialized"));
    }
    const spidPassport = new SpidPassport(
      app,
      expectedLoginPath,
      spidStrategyConfig
    );
    // tslint:disable: no-string-literal
    expect(spidPassport["config"]).toEqual(spidStrategyConfig);
    expect(spidPassport["app"]).toEqual(app);
    expect(spidPassport["loginPath"]).toEqual(expectedLoginPath);
    expect(spidPassport.spidStrategy).toEqual(undefined);
    done();
  });

  it("Run initialization of spidStrategy", async () => {
    if (app === undefined) {
      throw new Error("App not initialized");
    }
    const spidPassport = new SpidPassport(
      app,
      expectedLoginPath,
      spidStrategyConfig
    );
    await spidPassport.init();
    expect(spidPassport.spidStrategy).not.toEqual(undefined);
    expect(
      app._router.stack.filter(matchRoute(expectedLoginPath, "get"))
    ).toHaveLength(1);
  });

  it("Clear and reload new spid strategy", async () => {
    const newSpidStrategyConfig: ISpidStrategyConfig = {
      ...spidStrategyConfig,
      samlAttributeConsumingServiceIndex: samlAttributeConsumingServiceIndex + 1
    };
    if (app === undefined) {
      throw new Error("App not initialized");
    }
    const spidPassport = new SpidPassport(
      app,
      expectedLoginPath,
      spidStrategyConfig
    );
    await spidPassport.init();
    await spidPassport.clearAndReloadSpidStrategy(newSpidStrategyConfig);
    expect(spidPassport.spidStrategy).not.toEqual(undefined);
    expect(spidPassport["config"]).toEqual(newSpidStrategyConfig);
    expect(
      app._router.stack.filter(matchRoute(expectedLoginPath, "get"))
    ).toHaveLength(1);
  });

  it("Fail reload Spid strategy", async () => {
    if (app === undefined) {
      throw new Error("App not initialized");
    }
    const spidPassport = new SpidPassport(
      app,
      expectedLoginPath,
      spidStrategyConfig
    );
    await spidPassport.init();
    jest.spyOn(spid, "loadSpidStrategy").mockImplementation(() => {
      return Promise.reject(new Error("Error on load spid strategy"));
    });
    const newSpidStrategyConfig: ISpidStrategyConfig = {
      ...spidStrategyConfig,
      samlAttributeConsumingServiceIndex: samlAttributeConsumingServiceIndex + 1
    };
    const originalSpidStrategy = spidPassport.spidStrategy;
    try {
      await spidPassport.clearAndReloadSpidStrategy(newSpidStrategyConfig);
    } catch (e) {
      expect(e).toBe(SPID_RELOAD_ERROR);
      expect(spidPassport.spidStrategy).toEqual(originalSpidStrategy);
      expect(spidPassport["config"]).not.toEqual(newSpidStrategyConfig);
      expect(spidPassport["config"]).toEqual(spidStrategyConfig);
    }
  });
});
