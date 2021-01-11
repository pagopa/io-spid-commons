<img src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-b-lb.png" alt="SPID" data-canonical-src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-b-lb.png" width="500" height="98" />

[![License](https://img.shields.io/github/license/italia/spid-express.svg)](https://github.com/italia/spid-express/blob/master/LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/italia/spid-express.svg)](https://github.com/italia/spid-express/issues)
[![Join the #spid-express channel](https://img.shields.io/badge/Slack%20channel-%23spid--express-blue.svg)](https://app.slack.com/client/T6C27AXE0/C7ESTJS58)
[![Get invited](https://slack.developers.italia.it/badge.svg)](https://slack.developers.italia.it/)
[![SPID on forum.italia.it](https://img.shields.io/badge/Forum-spid-blue.svg)](https://forum.italia.it/c/spid/5)

# spid-express

spid-express è un middleware per [Express](https://expressjs.com) che implementa
SPID e Entra con CIE (Carta d'identità Elettronica).

Puoi usare questo pacchetto per integrare SPID o CIE in un'applicazione Express.

## Requisiti

* Redis (per caching delle sessioni di autenticazione)
* `passport-saml 1.2.0` (versione esatta)

## Uso

La funzione `withSpid()` abilita SPID su un'app Express esistente.
È disponibile un esempio dell'uso in [`src/example.ts`](src/example.ts).

```js
   withSpid({
     acs,                  // Funzione che riceve i dati al login dell'utente SPID
     app,                  // App Express
     appConfig,            // Endpoint dell'app
     doneCb,               // Callback (facoltativo)
     logout,               // Funzione da chiamare al logout SPID
     redisClient,          // Client Redis
     samlConfig,           // Configurazione del middleware
     serviceProviderConfig // Configurazione del Service Provider
   })
```

### `acs`

La funzione `acs()` (Assertion Consumer Service) riceve i dati dell'utente SPID
in `userPayload` se il login è avvenuto con successo. È definita come:

```js
   type AssertionConsumerServiceT = (
     userPayload: unknown
   ) => Promise<
     | IResponseErrorInternal
     | IResponseErrorValidation
     | IResponsePermanentRedirect
     | IResponseErrorForbiddenNotAuthorized
   >
```

`userPayload` è un oggetto le cui chiavi sono gli attributi SPID richiesti in
`requiredAttributes.attributes`(#serviceProviderConfig). Es:

```yaml
  {
     name: 'Carla'
     familyName: 'Rossi'
     fiscalNumber: 'RSSCRL32R82Y766D',
     email: 'foobar@example.com',
     ...
  }
```

### `app`

L'istanza dell'app Express.

### `appConfig`

L'oggetto `appConfig` configura gli endpoint dell'app. Es:

```js
   const appConfig: IApplicationConfig = {
     assertionConsumerServicePath: "/acs",
     clientErrorRedirectionUrl: "/error",
     clientLoginRedirectionUrl: "/error",
     loginPath: "/login",
     metadataPath: "/metadata",
     sloPath: "/logout"
   };
```

* **`assertionConsumerServicePath`**: L'endpoint al quale verranno POSTati i
  dati dell'utente dopo un login avvenuto con successo. È l'endpoint della
  funzione `acs()` e viene creato automaticamente.
* **`clientErrorRedirectionUrl`**: URL al quale redirigere in caso di errore interno.
* **`clientLoginRedirectionUrl`**: URL al quale redirigere in caso di login SPID
  fallito.
* **`loginPath`** L'endpoint che inizia la sessione SPID. Generalmente è l'endpoint
  chiamato da [spid-smart-button](https://github.com/italia/spid-smart-button).
  Viene creato automaticamente.
* **`metadataPath`**: L'endpoint del metadata. Viene creato automaticamente.
* **`sloPath`**: L'endpoint per il logout SPID. La [funzione collegata](#logout)
  è quella passata in `withSpid()`.

### `doneCb`

La funzione chiamata dopo ogni risposta SAML (facoltativa).

### `logout`

La funzione da chiamare al logout di SPID, definita come:

```js
    type LogoutT = () => Promise<IResponsePermanentRedirect>
```

### `redisClient`

L'istanza di `RedisClient` per connettersi a un server Redis.

### `samlConfig`

L'oggetto `samlConfig` configura il middleware. Es:

```js
   const samlConfig: SamlConfig = {
     RACComparison: "minimum",
     acceptedClockSkewMs: 0,
     attributeConsumingServiceIndex: "0",
     authnContext: "https://www.spid.gov.it/SpidL1",
     callbackUrl: "http://localhost:3000/acs",
     identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
     issuer: "https://spid.agid.gov.it/cd",
     logoutCallbackUrl: "http://localhost:3000/slo",
     privateCert: fs.readFileSync("./certs/key.pem", "utf-8"),
     validateInResponseTo: true
   };
 ```

* **`RACComparison`**: Impostare a "`minimum`".
* **`acceptedClockSkewMs`**: Impostare a `0`.
* **`attributeConsumingServiceIndex`**: Impostare all'indice degli attributi richiesti
  definito nel metadata. Se l'app è l'unica applicazione SPID del Service Provider,
  impostare a "`0`".
* **`authnContext`**: Livello SPID richiesto. "`https://www.spid.gov.it/SpidL1`",
  "`https://www.spid.gov.it/SpidL2`" o "`https://www.spid.gov.it/SpidL3`".
* **`callbackUrl`**: L'URL completo di [`assertionConsumerServicePath`](#appConfig)
* **`identifierFormat`**: Impostare a "`urn:oasis:names:tc:SAML:2.0:nameid-format:transient`"
* **`issuer`**: URL del Service Provider.
* **`logoutCallbackUrl`**: L'URL completo di [`sloPath`](#appConfig)
* **`privateCert`**: Stringa con la chiave privata del Service Provider in
  formato PEM.
* **`validateInResponseTo`**: Impostare a `true`.

### `serviceProviderConfig`

L'oggetto `serviceProviderConfig` contiene i parametri del Service Provider. Es:

```js
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
     spidCieUrl: "https://preproduzione.idserver.servizicie.interno.gov.it/idp/shibboleth?Metadata",
     spidTestEnvUrl: "https://spid-testenv2:8088",
     spidValidatorUrl: "http://localhost:8080",
     strictResponseValidation: {
       "http://localhost:8080": true,
       "https://spid-testenv2:8088": true
     }
   };
```

* **`IDPMetadataUrl`**: URL dei metadata degli IdP. Impostare a "`https://registry.spid.gov.it/metadata/idp/spid-entities-idps.xml`".
* **`organization`**: Oggetto con i dati del Service Provider.
* **`publicCert`**: Stringa con il certificato del Service Provider in formato PEM.
* **`requiredAttributes`**: La lista, in `attributes`, degli attributi richiesti
  (identificativi in <https://docs.italia.it/italia/spid/spid-regole-tecniche/it/stabile/attributi.html>).
* **`spidCieUrl`**: URL per l'accesso con Carta d'Identità elettronica
  ("Entra con CIE").
  Impostare a "`https://preproduzione.idserver.servizicie.interno.gov.it/idp/shibboleth?Metadata`"
  per lo sviluppo.
* **`spidTestEnvUrl`**: URL dell'istanza di [spid-testenv2](https://github.com/italia/spid-testenv2).
  Lasciare vuoto per disabilitare.
* **`spidValidatorUrl`**: URL dell'istanza di [spid-saml-check](https://github.com/italia/spid-saml-check).
  Lasciare vuoto per disabilitare.
* **`strictResponseValidation`**: Impostare come da esempio con gli URL di
  `spid-testenv2` e `spid-saml-check` (se abilitati).

## Avvio dell'applicazione di esempio integrata

L'applicazione di esempio (`src/example.ts`) può essere lanciata con:

### Al primo avvio

Al primo avvio o quando viene rifatto il build è necessario salvare
il metadata dell'applicazione.

1. `docker-compose up`
2. Ignorare l'errore su `conf/sp_metadata.xml`. L'app scaricherà i metadata di
   tutti gli IdP e al termine stamperà il messaggio
   `[spid-express] info: samlCert expire in 12 months`
3. Da un altro terminale
   `cd spid-testenv && curl http://localhost:3000/metadata -o sp_metadata.xml`
4. Fermare il `docker-compose` iniziale con `CTRL-C`.

### Avvii successivi

1. `docker-compose up`

Dopo il messaggio `[spid-express] info: samlCert expire in 12 months`) l'app sarà
pronta e in ascolto su <http://localhost:3000>.

Iniziare la sessione SPID con una GET su
[`http://localhost:3000/login?entityID=xx_testenv2`](http://localhost:3000/login?entityID=xx_testenv2).

Gli `entityID` che si possono usare in produzione sono "`lepidaid`", "`infocertid`",
"`sielteid`", "`namirialid`", "`timid`", "`arubaid`", "`posteid`", "`intesaid`"
e "`spiditalia`" (vedere [`src/config.ts`](src/config.ts)).

### Uso di Carta di Identità Elettronica (CIE)

Il middleware permette anche di interagire con gli IDP di collaudo e produzione di 
"Entra con CIE" dell'Istituto Poligrafico Zecca dello Stato. Non è presente al momento
un ambiente di sviluppo.

Per poter utilizzare l'ambiente di collaudo è necessario federarsi inviando un
modulo di richiesta come specificato nel documento delle regole tecniche CIE: 
[vedi qui](https://www.cartaidentita.interno.gov.it/CIE-ManualeOperativoperifornitoridiservizi.pdf)

Una volta federati, è possibile utilizzare lo stesso endpoint utilizzato per SPID 
per l'accesso con CIE: l'entityID è "`xx_servizicie`" in produzione e 
"`xx_servizicie_test`" in collaudo.

# Licenza

spid-express è rilasciato con [licenza MIT](LICENSE).
