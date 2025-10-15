package com.example.jwt_basics1.service;

import com.example.jwt_basics1.config.JwtUtil;
import com.example.jwt_basics1.dto.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.security.core.userdetails.UserDetails;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final JwtUtil jwtUtil;
    private final TokenBlacklistService tokenBlacklistService;
    private final CustomUserDetailsService customUserDetailsService;

    public AuthenticationResponse refresh(String refreshToken, String ipAddress) {
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            throw new IllegalArgumentException("Refresh token is missing");
        }
        if(ipAddress == null || ipAddress.trim().isEmpty()) {
            throw new IllegalArgumentException("IP address is missing");
        }
        String username = jwtUtil.extractUsername(refreshToken);
        System.out.println("Extracted username: " + username);
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

        if (!jwtUtil.validateToken(refreshToken, userDetails)) {
            throw new RuntimeException("Invalid or expired refresh token");
        }

        if(tokenBlacklistService.isTokenBlacklisted(refreshToken)) {
            throw new RuntimeException("Refresh token has been blacklisted");
        }
        String newAccessToken = jwtUtil.generateToken(null, userDetails,ipAddress);
        String newRefreshToken = jwtUtil.generateRefreshToken(userDetails,ipAddress);
        tokenBlacklistService.blacklistToken(refreshToken);
        return new AuthenticationResponse(newAccessToken, newRefreshToken);
    }
}