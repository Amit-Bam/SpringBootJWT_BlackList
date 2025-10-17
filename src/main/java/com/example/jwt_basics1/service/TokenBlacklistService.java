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

        private final ConcurrentHashMap<String, Date> blacklistedTokens = new ConcurrentHashMap<>();

        public void blacklistToken(String token) {
            removeExpiredTokens();
            Date expiration = jwtUtil.extractExpiration(token);
            blacklistedTokens.put(jwtUtil.extractJoinedUUID(token),expiration);
        }


        public boolean isTokenBlacklisted(String token) {
            removeExpiredTokens();
            return blacklistedTokens.containsKey(jwtUtil.extractJoinedUUID(token));
        }


        public synchronized void removeExpiredTokens() {
            Date now = new Date();
            blacklistedTokens.entrySet().removeIf(entry -> entry.getValue().before(now));
        }

    }