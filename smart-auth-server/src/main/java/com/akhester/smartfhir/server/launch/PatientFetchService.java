package com.akhester.smartfhir.server.launch;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.client.api.IGenericClient;
import com.akhester.smartfhir.server.SmartServerProperties;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Patient;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Shared FHIR patient search, used by both EHR-launch and standalone-launch patient
 * pickers.
 *
 * <p>Centralises the HAPI-client call and the FHIR-to-view-model mapping that was
 * previously duplicated in {@link LaunchPortalController} and
 * {@link StandalonePatientPickerController}.</p>
 *
 * <p>Throws on network or FHIR server errors — callers are responsible for catching
 * and presenting a user-friendly error message in the model.</p>
 */
@Service
public class PatientFetchService {

    private final FhirContext fhirContext;
    private final SmartServerProperties serverProperties;

    public PatientFetchService(FhirContext fhirContext,
                               SmartServerProperties serverProperties) {
        this.fhirContext       = fhirContext;
        this.serverProperties  = serverProperties;
    }

    /**
     * Searches the HAPI FHIR server for patients whose name matches {@code search}
     * (or all patients when {@code search} is null / blank), capped at 20 results.
     *
     * @param search optional partial name filter
     * @return list of view-model maps with keys {@code id}, {@code name},
     *         {@code dob}, {@code gender}
     */
    public List<Map<String, String>> fetchPatients(String search) {
        IGenericClient client = fhirContext.newRestfulGenericClient(
                serverProperties.fhirBaseUrl());

        var query = client.search().forResource(Patient.class);

        if (search != null && !search.isBlank()) {
            query = query.where(Patient.NAME.matches().value(search));
        }

        Bundle bundle = query.count(20)
                .returnBundle(Bundle.class)
                .execute();

        List<Map<String, String>> result = new ArrayList<>();
        for (Bundle.BundleEntryComponent entry : bundle.getEntry()) {
            if (entry.getResource() instanceof Patient patient) {
                String id = patient.getIdElement().getIdPart();

                String name = patient.getName().isEmpty() ? "Unknown"
                        : (patient.getNameFirstRep().getGivenAsSingleString()
                           + " " + patient.getNameFirstRep().getFamily()).trim();

                String dob    = patient.getBirthDateElement().getValueAsString();
                String gender = patient.getGender() != null
                        ? patient.getGender().toCode() : "unknown";

                result.add(Map.of(
                        "id",     id,
                        "name",   name,
                        "dob",    dob != null ? dob : "",
                        "gender", gender
                ));
            }
        }
        return result;
    }
}
