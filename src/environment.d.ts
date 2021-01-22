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
    }
  }
}

// If this file has no import/export statements (i.e. is a script)
// convert it into a module by adding an empty export statement.
export {}
