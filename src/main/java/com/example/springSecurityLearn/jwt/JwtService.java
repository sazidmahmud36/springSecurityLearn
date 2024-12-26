package com.example.springSecurityLearn.jwt;

import com.example.springSecurityLearn.entity.User;
import com.example.springSecurityLearn.repository.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.util.Date;

import javax.crypto.SecretKey;
import java.util.function.Function;

@Service
public class JwtService {
    @Autowired
    private TokenRepository tokenRepository;

    private final String SECURITY_KEY="5aytdn3RLAwtMc0AsVwjihXJGBmxCRaoviyzw17pCTzaWtQtxSazidD6HNoc3p8J";

    // get all part from token
    private Claims extractAllClaims(String token){

        return Jwts
                .parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

    }
    private SecretKey getSigningKey(){

        byte[] keyBytes= Decoders.BASE64URL.decode(SECURITY_KEY);
        return Keys.hmacShaKeyFor(keyBytes);

    }

    public String generateToken(User user){
        return Jwts
                .builder()
                .subject(user.getEmail()) // Set Email as Subject
                .claim("role", user.getRole()) // Add user Role to Payload
                .issuedAt(new Date(System.currentTimeMillis())) // Set Token issue ime
                .expiration(new Date(System.currentTimeMillis()+24*60*60*1000)) // Set Token Expire Time
                .signWith(getSigningKey()) // Sign the Token with Secreat key
                .compact(); // Build and Compacts the token into String
    }


    //Get UserName from token
    public String extractUserName(String token){
        return  extractClaim(token, Claims::getSubject);
    }



    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {

        return  extractClaim(token, Claims::getExpiration);

    }



    public  boolean isValid(String token, UserDetails user){

        String userName=extractUserName(token);

        boolean validToken=tokenRepository
                .findByToken(token)
                .map(t -> !t.isLogout()) //Check user is in login mode
                .orElse(false);

        return (userName.equals(user.getUsername()) && !isTokenExpired(token) && validToken);

    }


    // get User Role From Token
    public String extractUserRole(String token){
        return extractClaim(token, claims -> claims.get("role", String.class));
    }



    // Extract a specific Claim from the Token Claims
    public <T> T extractClaim(String token, Function<Claims, T> resolver){

        Claims claims=extractAllClaims(token);
        return resolver.apply(claims);

    }






}
