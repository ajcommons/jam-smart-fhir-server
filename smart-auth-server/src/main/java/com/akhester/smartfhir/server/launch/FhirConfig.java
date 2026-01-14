package com.akhester.smartfhir.server.launch;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.client.api.ServerValidationModeEnum;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Shared {@link FhirContext} singleton bean.
 * FhirContext.forR4() is expensive (~2-4s startup) — one instance for the whole app.
 */
@Configuration
public class FhirConfig {

    @Bean
    public FhirContext fhirContext() {
        FhirContext ctx = FhirContext.forR4();
        ctx.getRestfulClientFactory().setServerValidationMode(ServerValidationModeEnum.NEVER);
        return ctx;
    }
}
