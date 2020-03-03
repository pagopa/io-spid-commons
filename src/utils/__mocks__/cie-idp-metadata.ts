export default `<?xml version="1.0" encoding="UTF-8"?>
<!--
     This is example metadata only. Do *NOT* supply it as is without review,
     and do *NOT* provide it in real time to your partners.

     This metadata is not dynamic - it will not change as your configuration changes.
-->
<EntityDescriptor  xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" xmlns:xml="http://www.w3.org/XML/1998/namespace" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/POST/SSO">

    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol urn:oasis:names:tc:SAML:1.1:protocol urn:mace:shibboleth:1.0">

        <Extensions>
            <shibmd:Scope regexp="false">gov.it</shibmd:Scope>
            <!--
                Fill in the details for your IdP here

                        <mdui:UIInfo>
                            <mdui:DisplayName xml:lang="en">A Name for the IdP at idserver.servizicie.interno.gov.it</mdui:DisplayName>
                            <mdui:Description xml:lang="en">Enter a description of your IdP at idserver.servizicie.interno.gov.it</mdui:Description>
                            <mdui:Logo height="80" width="80">https://idserver.servizicie.interno.gov.it/Path/To/Logo.png</mdui:Logo>
                        </mdui:UIInfo>
            -->
        </Extensions>

        <KeyDescriptor use="signing">
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>
                        MIIDdTCCAl2gAwIBAgIUU79XEfveueyClDtLkqUlSPZ2o8owDQYJKoZIhvcNAQEL
                        BQAwLTErMCkGA1UEAwwiaWRzZXJ2ZXIuc2Vydml6aWNpZS5pbnRlcm5vLmdvdi5p
                        dDAeFw0xODEwMTkwODM1MDVaFw0zODEwMTkwODM1MDVaMC0xKzApBgNVBAMMImlk
                        c2VydmVyLnNlcnZpemljaWUuaW50ZXJuby5nb3YuaXQwggEiMA0GCSqGSIb3DQEB
                        AQUAA4IBDwAwggEKAoIBAQDHraj3iOTCIILTlOzicSEuFt03kKvQDqGWRd5o7s1W
                        7SP2EtcTmg3xron/sbrLEL/eMUQV/Biz6J4pEGoFpMZQHGxOVypmO7Nc8pkFot7y
                        UTApr6Ikuy4cUtbx0g5fkQLNb3upIg0Vg1jSnRXEvUCygr/9EeKCUOi/2ptmOVSL
                        ad+dT7TiRsZTwY3FvRWcleDfyYwcIMgz5dLSNLMZqwzQZK1DzvWeD6aGtBKCYPRf
                        tacHoESD+6bhukHZ6w95foRMJLOaBpkp+XfugFQioYvrM0AB1YQZ5DCQRhhc8jej
                        wdY+bOB3eZ1lJY7Oannfu6XPW2fcknelyPt7PGf22rNfAgMBAAGjgYwwgYkwHQYD
                        VR0OBBYEFK3Ah+Do3/zB9XjZ66i4biDpUEbAMGgGA1UdEQRhMF+CImlkc2VydmVy
                        LnNlcnZpemljaWUuaW50ZXJuby5nb3YuaXSGOWh0dHBzOi8vaWRzZXJ2ZXIuc2Vy
                        dml6aWNpZS5pbnRlcm5vLmdvdi5pdC9pZHAvc2hpYmJvbGV0aDANBgkqhkiG9w0B
                        AQsFAAOCAQEAVtpn/s+lYVf42pAtdgJnGTaSIy8KxHeZobKNYNFEY/XTaZEt9QeV
                        5efUMBVVhxKTTHN0046DR96WFYXs4PJ9Fpyq6Hmy3k/oUdmHJ1c2bwWF/nZ82CwO
                        O081Yg0GBcfPEmKLUGOBK8T55ncW+RSZadvWTyhTtQhLUtLKcWyzKB5aS3kEE5LS
                        zR8sw3owln9P41Mz+QtL3WeNESRHW0qoQkFotYXXW6Rvh69+GyzJLxvq2qd7D1qo
                        JgOMrarshBKKPk+ABaLYoEf/cru4e0RDIp2mD0jkGOGDkn9XUl+3ddALq/osTki6
                        CEawkhiZEo6ABEAjEWNkH9W3/ZzvJnWo6Q==
                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>

        </KeyDescriptor>
        <KeyDescriptor use="encryption">
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>
                        MIIDdTCCAl2gAwIBAgIUegfFpjtEsLaV0IL3qBEa0u81rGkwDQYJKoZIhvcNAQEL
                        BQAwLTErMCkGA1UEAwwiaWRzZXJ2ZXIuc2Vydml6aWNpZS5pbnRlcm5vLmdvdi5p
                        dDAeFw0xODEwMTkwODM1MDZaFw0zODEwMTkwODM1MDZaMC0xKzApBgNVBAMMImlk
                        c2VydmVyLnNlcnZpemljaWUuaW50ZXJuby5nb3YuaXQwggEiMA0GCSqGSIb3DQEB
                        AQUAA4IBDwAwggEKAoIBAQCe9W63GohPUaNbsoluWsVWfmtIyAIufqpmzYS4TiBv
                        E6l9LlDITsmShVBpiLPU4IDdvoPPBlDqgotofCnSjQxRhGky7tiy+pBObo13lN6d
                        03GgXNPZqZ+vKJinf8AmNe2UZ1ZbuvUtgS6+vx6P52/KNKx6YuDNmR3lLDhKZVDb
                        2wwR5qfsdnJIAORbJVWd8kI6GGhmrsmha7zARd0W+ueDtd/WLuAg3G7QWRocHPlP
                        TN/dPUbKS4O0cnJx0M5UERQ12PIdy641ps6P1v2OatpfSmZp/IlDLKJj9O9V49LM
                        nxF3VBJkTep2UQsQUc3rlelN2rYAlhURQQzRwpWO5WJvAgMBAAGjgYwwgYkwHQYD
                        VR0OBBYEFAQDr+o8YMapC4lje9upfeiwmFdtMGgGA1UdEQRhMF+CImlkc2VydmVy
                        LnNlcnZpemljaWUuaW50ZXJuby5nb3YuaXSGOWh0dHBzOi8vaWRzZXJ2ZXIuc2Vy
                        dml6aWNpZS5pbnRlcm5vLmdvdi5pdC9pZHAvc2hpYmJvbGV0aDANBgkqhkiG9w0B
                        AQsFAAOCAQEAb7gRYzTPEMQjQKiwI4/NdhzzaoKQjp2tu3UPZwsUHruyCbI+B/0k
                        C2SaSBaAKGT66yN9bPY2Vj4FuxtYmLSZZnatydF19hSu+lExCySKt16GBJ+D5HN7
                        OmVizRvJNE4+RF0bajpeXnMottLrcL5Ry/BivpxdnIQ9th2sMc7ev0IZtIGYCxGg
                        c5SAJCz4zuCcNiPANHDPdoxYEQ9EV9PNAUx8q9tjAhoRRiT2ovqT+Dowqax0AVOP
                        hRY5rA8WMccWAedO8iSSO8DTWomtoOKS9vjWrQxnsHaT8GXohC2OYgSdKsBchvjS
                        i1RIVkrqHoSHIK2XQapkl8YmD75JjrGNNA==
                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>

        </KeyDescriptor>

        <ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding" Location="https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML1/SOAP/ArtifactResolution" index="1"/>
        <ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/SOAP/ArtifactResolution" index="2"/>

        <!--
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idserver.servizicie.interno.gov.it/idp/profile/SAML2/Redirect/SLO"/>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SLO"/>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST-SimpleSign/SLO"/>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/SOAP/SLO"/>
        -->

        <SingleSignOnService Binding="urn:mace:shibboleth:1.0:profiles:AuthnRequest" Location="https://idserver.servizicie.interno.gov.it:8443/idp/profile/Shibboleth/SSO"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/POST/SSO"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/POST-SimpleSign/SSO"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/Redirect/SSO"/>

    </IDPSSODescriptor>


    <AttributeAuthorityDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol">

        <Extensions>
            <shibmd:Scope regexp="false">gov.it</shibmd:Scope>
        </Extensions>


        <KeyDescriptor use="signing">
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>
                        MIIDdTCCAl2gAwIBAgIUU79XEfveueyClDtLkqUlSPZ2o8owDQYJKoZIhvcNAQEL
                        BQAwLTErMCkGA1UEAwwiaWRzZXJ2ZXIuc2Vydml6aWNpZS5pbnRlcm5vLmdvdi5p
                        dDAeFw0xODEwMTkwODM1MDVaFw0zODEwMTkwODM1MDVaMC0xKzApBgNVBAMMImlk
                        c2VydmVyLnNlcnZpemljaWUuaW50ZXJuby5nb3YuaXQwggEiMA0GCSqGSIb3DQEB
                        AQUAA4IBDwAwggEKAoIBAQDHraj3iOTCIILTlOzicSEuFt03kKvQDqGWRd5o7s1W
                        7SP2EtcTmg3xron/sbrLEL/eMUQV/Biz6J4pEGoFpMZQHGxOVypmO7Nc8pkFot7y
                        UTApr6Ikuy4cUtbx0g5fkQLNb3upIg0Vg1jSnRXEvUCygr/9EeKCUOi/2ptmOVSL
                        ad+dT7TiRsZTwY3FvRWcleDfyYwcIMgz5dLSNLMZqwzQZK1DzvWeD6aGtBKCYPRf
                        tacHoESD+6bhukHZ6w95foRMJLOaBpkp+XfugFQioYvrM0AB1YQZ5DCQRhhc8jej
                        wdY+bOB3eZ1lJY7Oannfu6XPW2fcknelyPt7PGf22rNfAgMBAAGjgYwwgYkwHQYD
                        VR0OBBYEFK3Ah+Do3/zB9XjZ66i4biDpUEbAMGgGA1UdEQRhMF+CImlkc2VydmVy
                        LnNlcnZpemljaWUuaW50ZXJuby5nb3YuaXSGOWh0dHBzOi8vaWRzZXJ2ZXIuc2Vy
                        dml6aWNpZS5pbnRlcm5vLmdvdi5pdC9pZHAvc2hpYmJvbGV0aDANBgkqhkiG9w0B
                        AQsFAAOCAQEAVtpn/s+lYVf42pAtdgJnGTaSIy8KxHeZobKNYNFEY/XTaZEt9QeV
                        5efUMBVVhxKTTHN0046DR96WFYXs4PJ9Fpyq6Hmy3k/oUdmHJ1c2bwWF/nZ82CwO
                        O081Yg0GBcfPEmKLUGOBK8T55ncW+RSZadvWTyhTtQhLUtLKcWyzKB5aS3kEE5LS
                        zR8sw3owln9P41Mz+QtL3WeNESRHW0qoQkFotYXXW6Rvh69+GyzJLxvq2qd7D1qo
                        JgOMrarshBKKPk+ABaLYoEf/cru4e0RDIp2mD0jkGOGDkn9XUl+3ddALq/osTki6
                        CEawkhiZEo6ABEAjEWNkH9W3/ZzvJnWo6Q==
                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>

        </KeyDescriptor>
        <KeyDescriptor use="encryption">
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>
                        MIIDdTCCAl2gAwIBAgIUegfFpjtEsLaV0IL3qBEa0u81rGkwDQYJKoZIhvcNAQEL
                        BQAwLTErMCkGA1UEAwwiaWRzZXJ2ZXIuc2Vydml6aWNpZS5pbnRlcm5vLmdvdi5p
                        dDAeFw0xODEwMTkwODM1MDZaFw0zODEwMTkwODM1MDZaMC0xKzApBgNVBAMMImlk
                        c2VydmVyLnNlcnZpemljaWUuaW50ZXJuby5nb3YuaXQwggEiMA0GCSqGSIb3DQEB
                        AQUAA4IBDwAwggEKAoIBAQCe9W63GohPUaNbsoluWsVWfmtIyAIufqpmzYS4TiBv
                        E6l9LlDITsmShVBpiLPU4IDdvoPPBlDqgotofCnSjQxRhGky7tiy+pBObo13lN6d
                        03GgXNPZqZ+vKJinf8AmNe2UZ1ZbuvUtgS6+vx6P52/KNKx6YuDNmR3lLDhKZVDb
                        2wwR5qfsdnJIAORbJVWd8kI6GGhmrsmha7zARd0W+ueDtd/WLuAg3G7QWRocHPlP
                        TN/dPUbKS4O0cnJx0M5UERQ12PIdy641ps6P1v2OatpfSmZp/IlDLKJj9O9V49LM
                        nxF3VBJkTep2UQsQUc3rlelN2rYAlhURQQzRwpWO5WJvAgMBAAGjgYwwgYkwHQYD
                        VR0OBBYEFAQDr+o8YMapC4lje9upfeiwmFdtMGgGA1UdEQRhMF+CImlkc2VydmVy
                        LnNlcnZpemljaWUuaW50ZXJuby5nb3YuaXSGOWh0dHBzOi8vaWRzZXJ2ZXIuc2Vy
                        dml6aWNpZS5pbnRlcm5vLmdvdi5pdC9pZHAvc2hpYmJvbGV0aDANBgkqhkiG9w0B
                        AQsFAAOCAQEAb7gRYzTPEMQjQKiwI4/NdhzzaoKQjp2tu3UPZwsUHruyCbI+B/0k
                        C2SaSBaAKGT66yN9bPY2Vj4FuxtYmLSZZnatydF19hSu+lExCySKt16GBJ+D5HN7
                        OmVizRvJNE4+RF0bajpeXnMottLrcL5Ry/BivpxdnIQ9th2sMc7ev0IZtIGYCxGg
                        c5SAJCz4zuCcNiPANHDPdoxYEQ9EV9PNAUx8q9tjAhoRRiT2ovqT+Dowqax0AVOP
                        hRY5rA8WMccWAedO8iSSO8DTWomtoOKS9vjWrQxnsHaT8GXohC2OYgSdKsBchvjS
                        i1RIVkrqHoSHIK2XQapkl8YmD75JjrGNNA==
                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>

        </KeyDescriptor>

        <AttributeService Binding="urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding" Location="https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML1/SOAP/AttributeQuery"/>
        <!-- <AttributeService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/SOAP/AttributeQuery"/> -->
        <!-- If you uncomment the above you should add urn:oasis:names:tc:SAML:2.0:protocol to the protocolSupportEnumeration above -->

    </AttributeAuthorityDescriptor>

</EntityDescriptor>`;
