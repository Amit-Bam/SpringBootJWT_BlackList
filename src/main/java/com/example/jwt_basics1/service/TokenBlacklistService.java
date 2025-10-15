package com.example.jwt_basics1.service;

    import com.example.jwt_basics1.config.JwtUtil;
    import io.jsonwebtoken.Claims;
    import io.jsonwebtoken.JwtException;
    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.scheduling.annotation.Scheduled;
    import org.springframework.stereotype.Service;

    import java.util.Date;
    import java.util.concurrent.ConcurrentHashMap;

    @Service
    public class TokenBlacklistService {

        @Autowired
        private JwtUtil jwtUtil;

        // Using ConcurrentHashMap for thread safety with multiple sessions
        private final ConcurrentHashMap<String, Date> blacklistedTokens = new ConcurrentHashMap<>();
        private final ConcurrentHashMap<String, Long> userLogoutTimestamps = new ConcurrentHashMap<>();

        public void blacklistToken(String token) {
            // Explicitly blacklist this specific token
            Date expiration = jwtUtil.extractExpiration(token);
            blacklistedTokens.put(token,expiration);
        }

        public void blacklistUserTokensOnLogout(String username) {
            // Record the logout timestamp for this user
            userLogoutTimestamps.put(username, System.currentTimeMillis());
        }

        public boolean isTokenBlacklisted(String token) {
            // Check if token is explicitly blacklisted
            if (blacklistedTokens.containsKey(token)) {
                return true;
            }

            try {
                String username = jwtUtil.extractUsername(token);
                Date issuedAt = jwtUtil.extractIssuedAt(token);

                if (username != null && issuedAt != null && userLogoutTimestamps.containsKey(username)) {
                    // If this token was issued before the user logged out, it's invalid
                    return issuedAt.getTime() < userLogoutTimestamps.get(username);
                }
            } catch (Exception e) {
                // If we can't process the token, consider it invalid
                return true;
            }

            return false;
        }

        public synchronized void removeExpiredTokens() {
            Date now = new Date();
            blacklistedTokens.entrySet().removeIf(entry -> entry.getValue().before(now));
        }

    }