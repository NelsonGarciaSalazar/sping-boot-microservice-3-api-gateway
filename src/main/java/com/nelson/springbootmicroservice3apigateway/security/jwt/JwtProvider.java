package com.nelson.springbootmicroservice3apigateway.security.jwt;

import com.nelson.springbootmicroservice3apigateway.model.User;
import com.nelson.springbootmicroservice3apigateway.security.UserPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

public interface JwtProvider {

    String generateToken(UserPrincipal auth);

    String generateToken(User user);

    Authentication getAuthentication(HttpServletRequest request);

    boolean isTokenValid(HttpServletRequest request);
}
