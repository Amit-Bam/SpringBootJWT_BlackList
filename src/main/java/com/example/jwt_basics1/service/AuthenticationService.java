package com.example.jwt_basics1.service;

import com.example.jwt_basics1.config.JwtUtil;
import com.example.jwt_basics1.dto.AuthenticationRequest;
import com.example.jwt_basics1.dto.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final CustomUserDetailsService customUserDetailsService;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;


    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        // load the user details from the database using the username by calling the loadUserByUsername() method
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(authenticationRequest.getUsername());

        // check if the password matches the password in the database
        if (!passwordEncoder.matches(authenticationRequest.getPassword(), userDetails.getPassword())) {
            throw new AuthenticationServiceException("Invalid credentials");
        }
        if(authenticationRequest.getIpAddress() == null) {
            throw new IllegalArgumentException("IP address is missing");
        }
        String ipAddress = authenticationRequest.getIpAddress();
        // generate  the access token
        String accessToken = jwtUtil.generateToken(authenticationRequest, userDetails,ipAddress);

        // generate the refresh token
        String refreshToken = jwtUtil.generateRefreshToken(userDetails,ipAddress);
        // return the AuthenticationResponse object
        return new AuthenticationResponse(accessToken, refreshToken);
    }
}

