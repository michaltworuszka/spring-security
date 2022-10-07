package tworuszka.michal.springsecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
         return new BCryptPasswordEncoder(10); //this is the most popular encoder - Strength (parameter of method) tells encoder how strong should be the encoding of a password
    }
}
