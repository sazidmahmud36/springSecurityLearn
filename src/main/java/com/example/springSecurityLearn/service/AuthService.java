package com.example.springSecurityLearn.service;

import com.example.springSecurityLearn.entity.AuthenticationResponse;
import com.example.springSecurityLearn.entity.Role;
import com.example.springSecurityLearn.entity.Token;
import com.example.springSecurityLearn.entity.User;
import com.example.springSecurityLearn.jwt.JwtService;
import com.example.springSecurityLearn.repository.TokenRepository;
import com.example.springSecurityLearn.repository.UserRepository;
import jakarta.mail.MessagingException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TokenRepository tokenRepository;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;


    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService, TokenRepository tokenRepository, AuthenticationManager authenticationManager, EmailService emailService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.tokenRepository = tokenRepository;
        this.authenticationManager = authenticationManager;
        this.emailService = emailService;
    }

    private void saveUserToken(String jwt, User user) {
        Token token = new Token();
        token.setToken(jwt);
        token.setLogout(false);
        token.setUser(user);

        tokenRepository.save(token);
    }

    private void removeAllTokenByUser(User user) {

        List<Token> validTokens = tokenRepository.findAllTokenByUser(user.getId());
        if (validTokens.isEmpty()) {
            return;
        }
        validTokens.forEach(t -> {
            t.setLogout(true);
        });
        tokenRepository.saveAll(validTokens);
    }




    public AuthenticationResponse register(User user) {
        // We check that Already any user Exists with this email
        if(userRepository.findByEmail(user.getEmail()).isPresent()){

            return  new AuthenticationResponse(null, "User Already Exists");
        }

        // Encode user password to save DB
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole(Role.valueOf("USER"));
        user.setLock(true);
        user.setActive(false);

        userRepository.save(user);

        String jwt=jwtService.generateToken(user);
        saveUserToken(jwt, user);
        sendActivationEmail(user);

        return new AuthenticationResponse(jwt, "User Registration was Successful");
    }



    public  AuthenticationResponse authencate(User request){

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        User user=userRepository.findByEmail(request.getEmail()).orElseThrow();

        // Generate Token for Current User
        String jwt=jwtService.generateToken(user);

        //Remove all existing toke for this user
        removeAllTokenByUser(user);

        saveUserToken(jwt, user);

        return  new AuthenticationResponse(jwt, "User Login Successful");

    }





    private void sendActivationEmail(User user) {

        String activationLink="http://localhost:8080/active/"+user.getId();
        String mailText= " <h2> Dear </h2> "+user.getName()+","
                +"<p>Pls Click on the following link to confirm your registration </p>"
                +"<a href=\""+activationLink+"\">Active Account</a>";
        String subject="Confirm Registration";
        try{
            emailService.sendSimpleEmail(user.getEmail(), subject, mailText);
        }
        catch (MessagingException e){
            throw  new RuntimeException();

        }
    }

    public  String activeUser(long id){

        User user=userRepository.findById(id)
                .orElseThrow(()-> new RuntimeException("User not Found with this ID "+id));

        if(user !=null){
            user.setActive(true);
            userRepository.save(user);
            return "User Activated Successfully!";

        }else {
            return  "Invalid Activation Token!";
        }

    }


}
