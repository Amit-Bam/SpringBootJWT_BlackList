package com.example.jwt_basics1.config;

import java.util.concurrent.TimeUnit;

public class JwtProperties {

    // The EXPIRATION_TIME constant is used to set the expiration time of the JWT
    // 5 minutes, it is recommended to set this to 30 minutes
    public static final long ACCESS_TOKEN_EXPIRATION = 300_000;

    // Refresh token expiration (7 days)
    public static final long REFRESH_TOKEN_EXPIRATION = 604_800_000;
    // The TOKEN_PREFIX constant is used to prefix the JWT in the Authorization header
    public static final String TOKEN_PREFIX = "Bearer ";

    // The HEADER_STRING constant is used to set the key of the Authorization header
    public static final String HEADER_STRING = "Authorization";

}
