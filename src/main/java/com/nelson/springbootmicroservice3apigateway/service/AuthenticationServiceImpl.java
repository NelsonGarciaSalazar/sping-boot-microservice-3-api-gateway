package com.nelson.springbootmicroservice3apigateway.service;

import com.nelson.springbootmicroservice3apigateway.model.User;
import com.nelson.springbootmicroservice3apigateway.repository.UserRepository;
import com.nelson.springbootmicroservice3apigateway.security.UserPrincipal;
import com.nelson.springbootmicroservice3apigateway.security.jwt.JwtProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationServiceImpl implements  AuthenticationService {

    private AuthenticationManager authenticationManager;

    private JwtProvider jwtProvider;

    private UserRepository userRepository;

    public AuthenticationServiceImpl(AuthenticationManager authenticationManager, JwtProvider jwtProvider, UserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtProvider = jwtProvider;
        this.userRepository = userRepository;
    }

    @Override
    public User signInAndReturnJWT(User signInRequest)
    {
        User user = userRepository.findByEmail(signInRequest.getEmail())
            .orElseThrow(() -> new UsernameNotFoundException("El usuario no fue encontrado:" + signInRequest.getEmail()));

        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(user.getUsername(), signInRequest.getPassword())
        );

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        String jwt = jwtProvider.generateToken(userPrincipal);

        User sigInUser = userPrincipal.getUser();
        sigInUser.setToken(jwt);

        return sigInUser;
    }

}
