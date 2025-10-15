package com.example.jwt_basics1.config;

import com.example.jwt_basics1.service.TokenBlacklistService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class CustomLogoutHandler implements LogoutSuccessHandler {
    private final TokenBlacklistService tokenBlacklistService;
    private final JwtUtil jwtUtil;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) throws IOException {
        // Extract the token from Authorization header
        String token = extractTokenFromRequest(request);

        if (token != null) {
            // Add the access token to the blacklist
            tokenBlacklistService.blacklistToken(token);

            // Extract username to potentially blacklist related refresh tokens
            String username = jwtUtil.extractUsername(token);
            // Here you could implement logic to invalidate refresh tokens
            // associated with this user or this specific session

            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().write("Logout successful");
        }
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
