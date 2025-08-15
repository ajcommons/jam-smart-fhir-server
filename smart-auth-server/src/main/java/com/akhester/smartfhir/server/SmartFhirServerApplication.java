package com.akhester.smartfhir.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

/** SMART on FHIR Authorization Server — Spring Boot entry point. */
@SpringBootApplication
@ConfigurationPropertiesScan   // scans SmartServerProperties AND SmartIdpProperties
@EnableScheduling   // activates @Scheduled on LaunchContextService.purgeExpiredTokens()
public class SmartFhirServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(SmartFhirServerApplication.class, args);
    }
}
