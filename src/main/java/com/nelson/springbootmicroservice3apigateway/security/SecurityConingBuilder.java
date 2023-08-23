package com.nelson.springbootmicroservice3apigateway.security;

import org.springframework.security.crypto.password.PasswordEncoder;

public class SecurityConingBuilder {
    private CustomUserDetailsService customUserDetailsService;
    private PasswordEncoder passwordEncoder;

    public SecurityConingBuilder setCustomUserDetailsService(CustomUserDetailsService customUserDetailsService) {
        this.customUserDetailsService = customUserDetailsService;
        return this;
    }

    public SecurityConingBuilder setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        return this;
    }

    public SecurityConing createSecurityConing() {
        return new SecurityConing(customUserDetailsService, passwordEncoder);
    }
}