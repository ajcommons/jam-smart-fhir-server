package com.akhester.smartfhir.server.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Loads {@link Clinician} records from the database and wraps them in
 * {@link ClinicianUserDetails} for Spring Security's login flow.
 *
 * Spring Authorization Server calls this during form login to authenticate
 * the clinician before showing the consent/authorize page.
 */
@Service
public class CliniciansUserDetailsService implements UserDetailsService {

    private final ClinicianRepository repository;

    public CliniciansUserDetailsService(ClinicianRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {
        return repository.findByUsername(username)
                .map(ClinicianUserDetails::new)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "Clinician not found: " + username));
    }
}
