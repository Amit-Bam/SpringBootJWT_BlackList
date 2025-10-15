package com.example.jwt_basics1.dto;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/*
    * The AuthenticationResponse class is used to store the access token, refresh token, and roles
    * It is used in the authentication controller for login
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationResponse {
    private String accessToken;
    private String refreshToken;


}
