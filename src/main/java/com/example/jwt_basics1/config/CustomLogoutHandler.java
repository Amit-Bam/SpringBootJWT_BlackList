package com.example.jwt_basics1.config;

import com.example.jwt_basics1.service.TokenBlacklistService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
                                Authentication authentication) throws IOException, ServletException {

        String accessToken = extractTokenFromRequest(request);

        if (accessToken == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("No token provided");
            return;
        }
        if (tokenBlacklistService.isTokenBlacklisted(accessToken)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Token is already blacklisted");
            return;
        }
        if(jwtUtil.extractTokenType(accessToken).equals("refresh")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Provided token is not an access token");
            return;
        }
        try {
            tokenBlacklistService.blacklistToken(accessToken);

            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().write("Logout successful");
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Error during logout: " + e.getMessage());
        }
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7).trim();
        }
        return null;
    }
}