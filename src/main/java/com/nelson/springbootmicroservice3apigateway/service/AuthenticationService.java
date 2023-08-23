package com.nelson.springbootmicroservice3apigateway.service;

import com.nelson.springbootmicroservice3apigateway.model.User;

public interface AuthenticationService {
    User signInAndReturnJWT(User signInRequest);
}
