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


        public void blacklistToken(String token) {
            try {
                // Extract JTI and expiration date
                String jti = jwtUtil.extractJti(token);
                Date expiration = jwtUtil.extractExpiration(token);

                // Only store the JTI in blacklist, not the token itself
                if (jti != null && !jti.isEmpty()) {
                    blacklistedTokens.put(jti, expiration);
                }
            } catch (Exception e) {
                throw new JwtException(e.getMessage());
            }
        }

        public boolean isTokenBlacklisted(String token) {
            // Only check by JTI
            try {
                String jti = jwtUtil.extractJti(token);
                return jti != null && blacklistedTokens.containsKey(jti);
            } catch (Exception e) {
                return false;
            }
        }

        /**
         * Remove all expired tokens from the blacklist
         */
        public synchronized void removeExpiredTokens() {
            Date now = new Date();
            blacklistedTokens.entrySet().removeIf(entry -> entry.getValue().before(now));
        }

        /*
         * Scheduled task to clean up expired tokens

        @Scheduled(fixedRate = 3600000) // Run every hour
        public void scheduledCleanup() {
            removeExpiredTokens();
        }*/
    }