package com.example.jwt_basics1.dto;

/*
    * The AuthenticationRequest class is used to store the username and password
    * It is used in the authentication controller for login
 */

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationRequest {
    private String username;
    private String password;
    private String ipAddress;
}
