declare global {
  namespace NodeJS {
    interface ProcessEnv {
      METADATA_PUBLIC_CERT: string;
      METADATA_PRIVATE_CERT: string;
      ORG_ISSUER: string;
      ORG_URL: string;
      ORG_DISPLAY_NAME: string;
      ORG_NAME: string;
      AUTH_N_CONTEXT: string;
      SPID_ATTRIBUTES: string;
      ENDPOINT_ACS: string;
      ENDPOINT_ERROR: string;
      ENDPOINT_SUCCESS: string;
      ENDPOINT_LOGIN: string;
      ENDPOINT_METADATA: string;
      ENDPOINT_LOGOUT: string;
      SPID_VALIDATOR_URL: string;
      SPID_TESTENV_URL: string;
      NODE_ENV: 'development' | 'production';
      PORT?: string;
      USE_HTTPS: string;
      HTTPS_KEY: string;
      HTTPS_CRT: string;
      SERVICE_PROVIDER_TYPE: string;
      CONTACT_PERSON_OTHER_VAT_NUMBER: string;
      CONTACT_PERSON_OTHER_FISCAL_CODE: string;
      CONTACT_PERSON_OTHER_EMAIL_ADDRESS: string;
      CONTACT_PERSON_OTHER_TELEPHONE_NUMBER: string;
      CONTACT_PERSON_BILLING_IVA_IDPAESE: string;
      CONTACT_PERSON_BILLING_IVA_IDCODICE: string;
      CONTACT_PERSON_BILLING_IVA_DENOMINAZIONE: string;
      CONTACT_PERSON_BILLING_SEDE_INDIRIZZO: string;
      CONTACT_PERSON_BILLING_SEDE_NUMEROCIVICO: string;
      CONTACT_PERSON_BILLING_SEDE_CAP: string;
      CONTACT_PERSON_BILLING_SEDE_COMUNE: string;
      CONTACT_PERSON_BILLING_SEDE_PROVINCIA: string;
      CONTACT_PERSON_BILLING_SEDE_NAZIONE: string;
      CONTACT_PERSON_BILLING_COMPANY: string;
      CONTACT_PERSON_BILLING_EMAIL_ADDRESS: string;
      CONTACT_PERSON_BILLING_TELEPHONE_NUMBER: string;
    }
  }
}

// If this file has no import/export statements (i.e. is a script)
// convert it into a module by adding an empty export statement.
export {}
