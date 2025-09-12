package com.akhester.smartfhir.server.auth;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ClinicianRepository extends JpaRepository<Clinician, String> {
    Optional<Clinician> findByUsername(String username);
}
