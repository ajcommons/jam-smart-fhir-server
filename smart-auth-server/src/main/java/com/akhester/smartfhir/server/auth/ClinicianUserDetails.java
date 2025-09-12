package com.akhester.smartfhir.server.auth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * Spring Security {@link UserDetails} wrapper around {@link Clinician}.
 * Presented to Spring Authorization Server's login flow.
 */
public class ClinicianUserDetails implements UserDetails {

    private final Clinician clinician;

    public ClinicianUserDetails(Clinician clinician) {
        this.clinician = clinician;
    }

    public String getDisplayName()  { return clinician.getDisplayName(); }
    public String getFhirUserId()   { return clinician.getFhirUserId(); }

    @Override public String getUsername()  { return clinician.getUsername(); }
    @Override public String getPassword()  { return clinician.getPasswordHash(); }
    @Override public boolean isEnabled()   { return clinician.isEnabled(); }
    @Override public boolean isAccountNonExpired()    { return true; }
    @Override public boolean isAccountNonLocked()     { return true; }
    @Override public boolean isCredentialsNonExpired(){ return true; }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Always include ROLE_CLINICIAN; add ROLE_ADMIN for admin accounts.
        // Both roles are needed so an admin can also use the portal and launch apps.
        String role = clinician.getRole() != null ? clinician.getRole() : "CLINICIAN";
        if ("ADMIN".equalsIgnoreCase(role)) {
            return List.of(
                    new SimpleGrantedAuthority("ROLE_CLINICIAN"),
                    new SimpleGrantedAuthority("ROLE_ADMIN")
            );
        }
        return List.of(new SimpleGrantedAuthority("ROLE_CLINICIAN"));
    }
}
