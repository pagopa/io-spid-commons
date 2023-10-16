import * as t from "io-ts";
/* eslint-disable @typescript-eslint/naming-convention */
export const SPID_IDP_IDENTIFIERS = {
  "https://id.eht.eu": "ehtid",
  "https://id.lepida.it/idp/shibboleth": "lepidaid",
  "https://identity.infocert.it": "infocertid",
  "https://identity.sieltecloud.it": "sielteid",
  "https://idp.intesigroup.com": "intesiid",
  "https://idp.namirialtsp.com/idp": "namirialid",
  "https://login.id.tim.it/affwebservices/public/saml2sso": "timid",
  "https://loginspid.aruba.it": "arubaid",
  "https://loginspid.infocamere.it": "infocamereid",
  "https://posteid.poste.it": "posteid",
  "https://spid.register.it": "spiditalia",
  "https://spid.teamsystem.com/idp": "teamsystemid",
};

export const CIE_IDP_IDENTIFIERS = {
  "https://collaudo.idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO":
    "xx_servizicie_coll",
  "https://idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO":
    "xx_servizicie",
  "https://preproduzione.idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO":
    "xx_servizicie_test",
};

export const Issuer = t.union([
  t.keyof(SPID_IDP_IDENTIFIERS),
  t.keyof(CIE_IDP_IDENTIFIERS),
]);
export type Issuer = t.TypeOf<typeof Issuer>;

export const IDP_NAMES: Record<Issuer, string | undefined> = {
  // CIE IdP
  "https://collaudo.idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO":
    "CIE ID collaudo",
  "https://idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO":
    "CIE ID",
  "https://preproduzione.idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO":
    "CIE ID test",
  // SPID IdP
  // eslint-disable-next-line sort-keys
  "https://id.eht.eu": "Etna ID",
  "https://id.lepida.it/idp/shibboleth": "Lepida ID",
  "https://identity.infocert.it": "InfoCert ID",
  "https://identity.sieltecloud.it": "Sielte ID",
  "https://idp.intesigroup.com": "Intesi Group SPID",
  "https://idp.namirialtsp.com/idp": "Namirial ID",
  "https://login.id.tim.it/affwebservices/public/saml2sso": "Tim ID",
  "https://loginspid.aruba.it": "Aruba ID",
  "https://loginspid.infocamere.it": "ID Infocamere",
  "https://posteid.poste.it": "Poste ID",
  "https://spid.register.it": "SpidItalia",
  "https://spid.teamsystem.com/idp": "TeamSystem ID",
};

/*
 * @see https://www.agid.gov.it/sites/default/files/repository_files/regole_tecniche/tabella_attributi_idp.pdf
 */
export const SPID_USER_ATTRIBUTES = {
  address: "Indirizzo",
  companyName: "Nome azienda",
  dateOfBirth: "Data di nascita",
  digitalAddress: "Indirizzo elettronico",
  email: "Email",
  familyName: "Cognome",
  fiscalNumber: "Codice fiscale",
  gender: "Sesso",
  idCard: "Numero carta di identità",
  ivaCode: "Codice IVA",
  mobilePhone: "Numero di telefono",
  name: "Nome",
  placeOfBirth: "Luogo di nascita",
  registeredOffice: "Ufficio",
  spidCode: "Codice SPID",
};

export const SPID_LEVELS = {
  SpidL1: "https://www.spid.gov.it/SpidL1",
  SpidL2: "https://www.spid.gov.it/SpidL2",
  SpidL3: "https://www.spid.gov.it/SpidL3",
};
export type SPID_LEVELS = typeof SPID_LEVELS;

export const SPID_URLS = {
  "https://www.spid.gov.it/SpidL1": "SpidL1",
  "https://www.spid.gov.it/SpidL2": "SpidL2",
  "https://www.spid.gov.it/SpidL3": "SpidL3",
};
