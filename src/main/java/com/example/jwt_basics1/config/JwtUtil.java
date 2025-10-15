package com.example.jwt_basics1.config;

import com.example.jwt_basics1.dto.AuthenticationRequest;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.crypto.Data;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;


@Component
public class JwtUtil {

    private final Key key;  // Store the generated key in a field

    public JwtUtil() {
        try {
            // private final String SECRET_KEY = JwtProperties.SECRET;
            KeyGenerator secretKeyGen = KeyGenerator.getInstance("HmacSHA256");
            this.key = Keys.hmacShaKeyFor(secretKeyGen.generateKey().getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }

    private Key getKey() {
        return this.key;  // Use the stored key
    }

    // Generate a JWT token for a user, first time login
    public String generateToken(AuthenticationRequest authenticationRequest,
                                UserDetails userDetails,String ipAddress) {

        Map<String, Object> claims = new HashMap<>();

        return Jwts.builder()
                .claims()
                .add(claims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + JwtProperties.ACCESS_TOKEN_EXPIRATION))
                .id(UUID.randomUUID().toString())
                .and()
                .claim("roles", userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .claim("issuedBy", "learning JWT with Spring Security")
                .claim("typ", "access")
                .claim("ip", ipAddress)
                .signWith(getKey())
                .compact();
    }

    public String generateRefreshToken(UserDetails userDetails,String ipAddress) {
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + JwtProperties.REFRESH_TOKEN_EXPIRATION))
                .id(UUID.randomUUID().toString())
                .claim("typ", "refresh")
                .claim("ip", ipAddress)
                .signWith(getKey())
                .compact();
    }

    // Extract the expiration date from a JWT token and implicitly validate the token
    // This implementation implicitly validates the signature when extracting claims:
    public boolean validateToken(String token, UserDetails userDetails) {
        try {
            // extract the username from the JWT token
            String username = extractUsername(token);
            // If signature verification fails, extractUsername will throw an exception.

            // check if the username extracted from the JWT token matches the username in the UserDetails object
            // and the token is not expired
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (Exception e) {
            // Handle the invalid signature here
            throw new RuntimeException("The token signature is invalid: " + e.getMessage());
        }
        // Other exceptions related to token parsing can also be caught here if necessary
    }

    // Extract the username from a JWT token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractIpAddress(String token) {
        return extractClaim(token, claims -> claims.get("ip", String.class));
    }

    private <T> T extractClaim(String string, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(string);
        return claimsResolver.apply(claims);
    }

    // Extract all claims from a JWT token
    private Claims extractAllClaims(String token) {
        SecretKey secretKey = (SecretKey) getKey();
        return Jwts
                .parser()
                .verifyWith(secretKey)
                .build().parseSignedClaims(token).getPayload();
    }

    // Check if a JWT token is expired
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date(System.currentTimeMillis()));
    }

    public String extractJti(String token) {
        return extractClaim(token, Claims::getId);
    }

    public boolean isValidTokenStructure(String token) {
        try {
            extractAllClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    public Date extractIssuedAt(String token) {
        return extractClaim(token, Claims::getIssuedAt);
    }
    // Extract the expiration date from a JWT token
    public Date extractExpiration(String token) {

        return extractClaim(token, Claims::getExpiration);
    }
    public String extractTokenType(String token) {
        return extractClaim(token, claims -> claims.get("typ", String.class));
    }


}
