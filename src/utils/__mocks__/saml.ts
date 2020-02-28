export const samlResponse = `<samlp:Response Destination="http://localhost:3000/acs" ID="_7080f453-78cb-4f57-9692-62dc8a5c23e8" InResponseTo="_2d2a89e99c7583e221b4" IssueInstant="2020-02-26T07:27:42Z" Version="2.0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">
    http://localhost:8080
</saml:Issuer>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_7080f453-78cb-4f57-9692-62dc8a5c23e8">
            <ds:Transforms>
                <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            </ds:Transforms>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>
                TF1ulWGxyd1WLVdSAqBIamJFuM2asyon8TiXFA5MKRk=
            </ds:DigestValue>
        </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>
        riM6BMi4m5VSG26SrSJ7oB5Sk2TYWAUWcQOeE0oeKEDvBbDSXYfMCed5RD8ZCaD340OdmYBNylW8WsegTR0Ejxlusjg/KbLfDFlTpFA6kQEI02A7LFjlWL1XR+t/jE2101zEcZQHp01R8oALxrMzicW591h12l8Y0HtoMCYTOoAThsyk7D+ce/+Jh4Ogn5xUtAm7NpXGuMRChIhVuhfvQ3l7rDxFU+N+CHc7mfLxRZFooQn1zmHS3Ccd/O8N1Tnx+ivCIzozDa9n35S5bzSqiVHBgoa3kEUsQB+ZEn38Y8gOWJgRpPi6txorjWj2+NAmzGH2DJ0tNQAuGc2B4Eu5uQ==
    </ds:SignatureValue>
    <ds:KeyInfo>
        <ds:X509Data>
            <ds:X509Certificate>
                MIIEGDCCAwCgAwIBAgIJAOrYj9oLEJCwMA0GCSqGSIb3DQEBCwUAMGUxCzAJBgNVBAYTAklUMQ4wDAYDVQQIEwVJdGFseTENMAsGA1UEBxMEUm9tZTENMAsGA1UEChMEQWdJRDESMBAGA1UECxMJQWdJRCBURVNUMRQwEgYDVQQDEwthZ2lkLmdvdi5pdDAeFw0xOTA0MTExMDAyMDhaFw0yNTAzMDgxMDAyMDhaMGUxCzAJBgNVBAYTAklUMQ4wDAYDVQQIEwVJdGFseTENMAsGA1UEBxMEUm9tZTENMAsGA1UEChMEQWdJRDESMBAGA1UECxMJQWdJRCBURVNUMRQwEgYDVQQDEwthZ2lkLmdvdi5pdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8kJVo+ugRrbbv9xhXCuVrqi4B7/MQzQc62ocwlFFujJNd4m1mXkUHFbgvwhRkQqo2DAmFeHiwCkJT3K1eeXIFhNFFroEzGPzONyekLpjNvmYIs1CFvirGOj0bkEiGaKEs+/umzGjxIhy5JQlqXE96y1+Izp2QhJimDK0/KNij8I1bzxseP0Ygc4SFveKS+7QO+PrLzWklEWGMs4DM5Zc3VRK7g4LWPWZhKdImC1rnS+/lEmHSvHisdVp/DJtbSrZwSYTRvTTz5IZDSq4kAzrDfpj16h7b3t3nFGc8UoY2Ro4tRZ3ahJ2r3b79yK6C5phY7CAANuW3gDdhVjiBNYs0CAwEAAaOByjCBxzAdBgNVHQ4EFgQU3/7kV2tbdFtphbSA4LH7+w8SkcwwgZcGA1UdIwSBjzCBjIAU3/7kV2tbdFtphbSA4LH7+w8SkcyhaaRnMGUxCzAJBgNVBAYTAklUMQ4wDAYDVQQIEwVJdGFseTENMAsGA1UEBxMEUm9tZTENMAsGA1UEChMEQWdJRDESMBAGA1UECxMJQWdJRCBURVNUMRQwEgYDVQQDEwthZ2lkLmdvdi5pdIIJAOrYj9oLEJCwMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJNFqXg/V3aimJKUmUaqmQEEoSc3qvXFITvT5f5bKw9yk/NVhR6wndL+z/24h1OdRqs76blgH8k116qWNkkDtt0AlSjQOx5qvFYh1UviOjNdRI4WkYONSw+vuavcx+fB6O5JDHNmMhMySKTnmRqTkyhjrch7zaFIWUSV7hsBuxpqmrWDoLWdXbV3eFH3mINA5AoIY/m0bZtzZ7YNgiFWzxQgekpxd0vcTseMnCcXnsAlctdir0FoCZztxMuZjlBjwLTtM6Ry3/48LMM8Z+lw7NMciKLLTGQyU8XmKKSSOh0dGh5Lrlt5GxIIJkH81C0YimWebz8464QPL3RbLnTKg+c=
            </ds:X509Certificate>
        </ds:X509Data>
    </ds:KeyInfo>
</ds:Signature>
<samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
</samlp:Status>
<saml:Assertion ID="_43568006-96d4-4dcc-84da-d98e01ea3a28" IssueInstant="2020-02-26T07:27:42Z" Version="2.0" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">
        http://localhost:8080
    </saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <ds:Reference URI="#_43568006-96d4-4dcc-84da-d98e01ea3a28">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>
                    /VIQSQkyyNQkdlgLOCFcTAg0Oy78b2Sy9GcaWeO6hb8=
                </ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>
            ZwOttAyJZ774CPdnfjnvExwqtRXS3cvXqgo/nnPF2CsZmoBd0V11FqgXpj2hD5HkQ4fiwpNjn319SeId8s9M8RBfWPVzD52pgm1M3nT76+qDf+GWrCnK8CgkskPId798BugCmgPuHul9XKKDKC0Ajj4THtetRklvmxkpTzJy8CgwV79pbQwLMTHsiIRed3X25rjqhtuVUBWB2BKN0RC4bsoKBrDwa4UYDZ/4n68zm0AVNP8xpTOgGDm1sGeMwqdmccITDk17OLWUsgX2WGPdwFIAUsLfs1zw9z/lF5wwEuaz7GxS3pg5P3yGg6VqM7fj4HBuWop/oNxYUHixULxbQw==
        </ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>
                    MIIEGDCCAwCgAwIBAgIJAOrYj9oLEJCwMA0GCSqGSIb3DQEBCwUAMGUxCzAJBgNVBAYTAklUMQ4wDAYDVQQIEwVJdGFseTENMAsGA1UEBxMEUm9tZTENMAsGA1UEChMEQWdJRDESMBAGA1UECxMJQWdJRCBURVNUMRQwEgYDVQQDEwthZ2lkLmdvdi5pdDAeFw0xOTA0MTExMDAyMDhaFw0yNTAzMDgxMDAyMDhaMGUxCzAJBgNVBAYTAklUMQ4wDAYDVQQIEwVJdGFseTENMAsGA1UEBxMEUm9tZTENMAsGA1UEChMEQWdJRDESMBAGA1UECxMJQWdJRCBURVNUMRQwEgYDVQQDEwthZ2lkLmdvdi5pdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8kJVo+ugRrbbv9xhXCuVrqi4B7/MQzQc62ocwlFFujJNd4m1mXkUHFbgvwhRkQqo2DAmFeHiwCkJT3K1eeXIFhNFFroEzGPzONyekLpjNvmYIs1CFvirGOj0bkEiGaKEs+/umzGjxIhy5JQlqXE96y1+Izp2QhJimDK0/KNij8I1bzxseP0Ygc4SFveKS+7QO+PrLzWklEWGMs4DM5Zc3VRK7g4LWPWZhKdImC1rnS+/lEmHSvHisdVp/DJtbSrZwSYTRvTTz5IZDSq4kAzrDfpj16h7b3t3nFGc8UoY2Ro4tRZ3ahJ2r3b79yK6C5phY7CAANuW3gDdhVjiBNYs0CAwEAAaOByjCBxzAdBgNVHQ4EFgQU3/7kV2tbdFtphbSA4LH7+w8SkcwwgZcGA1UdIwSBjzCBjIAU3/7kV2tbdFtphbSA4LH7+w8SkcyhaaRnMGUxCzAJBgNVBAYTAklUMQ4wDAYDVQQIEwVJdGFseTENMAsGA1UEBxMEUm9tZTENMAsGA1UEChMEQWdJRDESMBAGA1UECxMJQWdJRCBURVNUMRQwEgYDVQQDEwthZ2lkLmdvdi5pdIIJAOrYj9oLEJCwMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJNFqXg/V3aimJKUmUaqmQEEoSc3qvXFITvT5f5bKw9yk/NVhR6wndL+z/24h1OdRqs76blgH8k116qWNkkDtt0AlSjQOx5qvFYh1UviOjNdRI4WkYONSw+vuavcx+fB6O5JDHNmMhMySKTnmRqTkyhjrch7zaFIWUSV7hsBuxpqmrWDoLWdXbV3eFH3mINA5AoIY/m0bZtzZ7YNgiFWzxQgekpxd0vcTseMnCcXnsAlctdir0FoCZztxMuZjlBjwLTtM6Ry3/48LMM8Z+lw7NMciKLLTGQyU8XmKKSSOh0dGh5Lrlt5GxIIJkH81C0YimWebz8464QPL3RbLnTKg+c=
                </ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>
    <saml:Subject>
        <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" NameQualifier="https://validator.spid.gov.it">
                _61c0122d-5e8e-48e5-98ce-d43bb3903404
        </saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData InResponseTo="_2d2a89e99c7583e221b4" NotOnOrAfter="${new Date().getFullYear() +
              1}-02-26T07:32:05Z" Recipient="http://localhost:3000/acs"/>
        </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2020-02-26T07:27:42Z" NotOnOrAfter="${new Date().getFullYear() +
      1}-02-26T07:32:05Z">
        <saml:AudienceRestriction>
            <saml:Audience>
                https://spid.agid.gov.it/cd
            </saml:Audience>
        </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2020-02-26T07:27:42Z" SessionIndex="_09d40021-a5f7-4c1c-8388-cd737546eec3">
        <saml:AuthnContext>
            <saml:AuthnContextClassRef>
                https://www.spid.gov.it/SpidL2
            </saml:AuthnContextClassRef>
        </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
        <saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">
                SpidValidator
            </saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="familyName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">
                AgID
            </saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="fiscalNumber" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">
                TINIT-GDASDV00A01H501J
            </saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="mobilePhone" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">
                +393331234567
            </saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">
                spid.tech@agid.gov.it
            </saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="address" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">
                Via Listz 21 00144 Roma
            </saml:AttributeValue>
        </saml:Attribute>
    </saml:AttributeStatement>
</saml:Assertion>
</samlp:Response>`;

export const samlRequest = `<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_2d2a89e99c7583e221b4" Version="2.0" IssueInstant="2020-02-26T07:27:00Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Destination="http://localhost:8080/samlsso" ForceAuthn="true" AssertionConsumerServiceURL="http://localhost:3000/acs" AttributeConsumingServiceIndex="0">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" NameQualifier="https://spid.agid.gov.it/cd" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">
        https://spid.agid.gov.it/cd
    </saml:Issuer>
    <samlp:NameIDPolicy xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>
    <samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Comparison="exact">
        <saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            https://www.spid.gov.it/SpidL2
        </saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>`;

export const samlResponseCIE = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response Destination="https://app-backend.dev.io.italia.it/assertionConsumerService" ID="_36e7b2c177afab6db4302732a68403cb" InResponseTo="_61395d807fb9fe6a869b" IssueInstant="2020-02-27T13:40:57.746Z" Version="2.0" 
  xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" 
  xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/POST/SSO</saml2:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#_36e7b2c177afab6db4302732a68403cb">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
            <ec:InclusiveNamespaces PrefixList="xsd" 
              xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transform>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>3UGuOlUuag/oPOIif31jpuIJT829Eab+2dSEDegDlmU=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>
AIa2vTA8uOKizFvCqNchj4Dby8eDOi5UaOEZYJ4NV0RorEj2wkSFbhX65FYLt68VUGY5YR1tqDfl d0ApvcdtkH4gucq2aCd1zTq8yk5dXp10IC49YdLXlDCRh3QcgulIDZhZs/K2nTEzrrfHC7dibYv/ vk/tY5AOih2jIqNslt1gxopuLREUTyG1NC7CcqfwhxCxxs1z5ngcN1D/cZv9sQT85lzwGCU65+5G ySdiSr0WzHEEcT1k9WnDwqW27i0tbCwC2NZ3xOHl0X7mKb35TzhdMpAz74ADnalk833EjZdVHu6x XdG5KqmjIW+mrddO71jDRXQ1eMrQBeCAfRQ0Mg==
    </ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>MIIDdTCCAl2gAwIBAgIUU79XEfveueyClDtLkqUlSPZ2o8owDQYJKoZIhvcNAQELBQAwLTErMCkG A1UEAwwiaWRzZXJ2ZXIuc2Vydml6aWNpZS5pbnRlcm5vLmdvdi5pdDAeFw0xODEwMTkwODM1MDVa Fw0zODEwMTkwODM1MDVaMC0xKzApBgNVBAMMImlkc2VydmVyLnNlcnZpemljaWUuaW50ZXJuby5n b3YuaXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDHraj3iOTCIILTlOzicSEuFt03 kKvQDqGWRd5o7s1W7SP2EtcTmg3xron/sbrLEL/eMUQV/Biz6J4pEGoFpMZQHGxOVypmO7Nc8pkF ot7yUTApr6Ikuy4cUtbx0g5fkQLNb3upIg0Vg1jSnRXEvUCygr/9EeKCUOi/2ptmOVSLad+dT7Ti RsZTwY3FvRWcleDfyYwcIMgz5dLSNLMZqwzQZK1DzvWeD6aGtBKCYPRftacHoESD+6bhukHZ6w95 foRMJLOaBpkp+XfugFQioYvrM0AB1YQZ5DCQRhhc8jejwdY+bOB3eZ1lJY7Oannfu6XPW2fcknel yPt7PGf22rNfAgMBAAGjgYwwgYkwHQYDVR0OBBYEFK3Ah+Do3/zB9XjZ66i4biDpUEbAMGgGA1Ud EQRhMF+CImlkc2VydmVyLnNlcnZpemljaWUuaW50ZXJuby5nb3YuaXSGOWh0dHBzOi8vaWRzZXJ2 ZXIuc2Vydml6aWNpZS5pbnRlcm5vLmdvdi5pdC9pZHAvc2hpYmJvbGV0aDANBgkqhkiG9w0BAQsF AAOCAQEAVtpn/s+lYVf42pAtdgJnGTaSIy8KxHeZobKNYNFEY/XTaZEt9QeV5efUMBVVhxKTTHN0 046DR96WFYXs4PJ9Fpyq6Hmy3k/oUdmHJ1c2bwWF/nZ82CwOO081Yg0GBcfPEmKLUGOBK8T55ncW +RSZadvWTyhTtQhLUtLKcWyzKB5aS3kEE5LSzR8sw3owln9P41Mz+QtL3WeNESRHW0qoQkFotYXX W6Rvh69+GyzJLxvq2qd7D1qoJgOMrarshBKKPk+ABaLYoEf/cru4e0RDIp2mD0jkGOGDkn9XUl+3 ddALq/osTki6CEawkhiZEo6ABEAjEWNkH9W3/ZzvJnWo6Q==</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </saml2p:Status>
  <saml2:Assertion ID="_6aa64187239cb0852096c42c33e176ca" IssueInstant="2020-02-27T13:40:57.746Z" Version="2.0" 
    xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" 
    xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <saml2:Issuer>https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/POST/SSO</saml2:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_6aa64187239cb0852096c42c33e176ca">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
              <ec:InclusiveNamespaces PrefixList="xsd" 
                xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            </ds:Transform>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>5nSMW/zHmyhaVE4vWyxZvHMBDQWgktouXeWl9fKe504=</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>
UJ23xMKOYhCcRVunnDgor2WLqHEgYeyaAhHr16+kkO6poPog2a9PoiqGUU0Dg+YMvHRJVq0h0sKz M1zeVN1eR3JHIB8HAYtWDDxqTe/rTZcQ1lPWEA+bGqUlLTVc2ukvC4NSB17FT1j7VDIBL3UcdlQc SvR7W6Xw/D+J9Row4iX+rmsJRTy0I+8xj3FdRxMRGR+mSPhpZ1NbINMcSwOV9b+NXbQKqbHhqfH7 SJTGbS/RBZTzFX42jmrAM57TCRG/hwyt6TZyCY29n4dsa0xHGD8sLOvQZ5Zk7qB0HD2DSp31Fjpw zyklYfmGoXrkjdUNnUVyWck+cQXHaXJyokaTNA==
      </ds:SignatureValue>
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIDdTCCAl2gAwIBAgIUU79XEfveueyClDtLkqUlSPZ2o8owDQYJKoZIhvcNAQELBQAwLTErMCkG A1UEAwwiaWRzZXJ2ZXIuc2Vydml6aWNpZS5pbnRlcm5vLmdvdi5pdDAeFw0xODEwMTkwODM1MDVa Fw0zODEwMTkwODM1MDVaMC0xKzApBgNVBAMMImlkc2VydmVyLnNlcnZpemljaWUuaW50ZXJuby5n b3YuaXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDHraj3iOTCIILTlOzicSEuFt03 kKvQDqGWRd5o7s1W7SP2EtcTmg3xron/sbrLEL/eMUQV/Biz6J4pEGoFpMZQHGxOVypmO7Nc8pkF ot7yUTApr6Ikuy4cUtbx0g5fkQLNb3upIg0Vg1jSnRXEvUCygr/9EeKCUOi/2ptmOVSLad+dT7Ti RsZTwY3FvRWcleDfyYwcIMgz5dLSNLMZqwzQZK1DzvWeD6aGtBKCYPRftacHoESD+6bhukHZ6w95 foRMJLOaBpkp+XfugFQioYvrM0AB1YQZ5DCQRhhc8jejwdY+bOB3eZ1lJY7Oannfu6XPW2fcknel yPt7PGf22rNfAgMBAAGjgYwwgYkwHQYDVR0OBBYEFK3Ah+Do3/zB9XjZ66i4biDpUEbAMGgGA1Ud EQRhMF+CImlkc2VydmVyLnNlcnZpemljaWUuaW50ZXJuby5nb3YuaXSGOWh0dHBzOi8vaWRzZXJ2 ZXIuc2Vydml6aWNpZS5pbnRlcm5vLmdvdi5pdC9pZHAvc2hpYmJvbGV0aDANBgkqhkiG9w0BAQsF AAOCAQEAVtpn/s+lYVf42pAtdgJnGTaSIy8KxHeZobKNYNFEY/XTaZEt9QeV5efUMBVVhxKTTHN0 046DR96WFYXs4PJ9Fpyq6Hmy3k/oUdmHJ1c2bwWF/nZ82CwOO081Yg0GBcfPEmKLUGOBK8T55ncW +RSZadvWTyhTtQhLUtLKcWyzKB5aS3kEE5LSzR8sw3owln9P41Mz+QtL3WeNESRHW0qoQkFotYXX W6Rvh69+GyzJLxvq2qd7D1qoJgOMrarshBKKPk+ABaLYoEf/cru4e0RDIp2mD0jkGOGDkn9XUl+3 ddALq/osTki6CEawkhiZEo6ABEAjEWNkH9W3/ZzvJnWo6Q==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </ds:Signature>
    <saml2:Subject>
      <saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" NameQualifier="https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/POST/SSO" SPNameQualifier="https://app-backend.dev.io.italia.it">AAdzZWNyZXQxqDU6XhTO1MGlMAoXjWFIOcPfK4AhIPsnBAoTNelku/jA7/XaogQJhOrgxCiAIqavL2GUQqQ7VMYPRryyteifD34fsyrHmbPNr1Tz2YJe8wgENUlDvaY31unC/P1kwqTZ17jQYw3qoVZs4neWi9ZUo9j8BoiDAHdoyOOoTiVbDA==</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData Address="85.44.51.73" InResponseTo="_61395d807fb9fe6a869b" NotOnOrAfter="${new Date().getFullYear() +
          1}-02-26T07:32:05Z" Recipient="https://app-backend.dev.io.italia.it/assertionConsumerService"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="2020-02-27T13:40:57.746Z" NotOnOrAfter="${new Date().getFullYear() +
      1}-02-26T07:32:05Z">
      <saml2:AudienceRestriction>
        <saml2:Audience>https://app-backend.dev.io.italia.it</saml2:Audience>
      </saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="2020-02-27T13:40:50.087Z" SessionIndex="_ce30d320de8285858cc8f6383750b09e">
      <saml2:SubjectLocality Address="85.44.51.73"/>
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>https://www.spid.gov.it/SpidL3</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
    <saml2:AttributeStatement>
      <saml2:Attribute FriendlyName="Data di Nascita" Name="dateOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">1964-12-30</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="Codice Fiscale" Name="fiscalNumber" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">TINIT-RSSBNC64T70G677R</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="Nome" Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">BIANCA</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="Cognome" Name="familyName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">ROSSI</saml2:AttributeValue>
      </saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>
`;
