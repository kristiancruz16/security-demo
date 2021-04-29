package com.springframework.securitydemo.auth;


import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static com.springframework.securitydemo.security.ApplicationUserRole.*;

@Repository
@Profile("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao{

    private final PasswordEncoder passwordEncoder;

    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers().stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();

    }

    private List<ApplicationUser> getApplicationUsers (){
         List<ApplicationUser> applicationUsers = Arrays.asList(
                new ApplicationUser("annasmith",passwordEncoder.encode("password"), STUDENT.getGrantedAuthorities(),
                        true,true,true,true),
                 new ApplicationUser("kristian",passwordEncoder.encode("password123"),ADMIN.getGrantedAuthorities(),
                         true,true,true,true),
                 new ApplicationUser("bella",passwordEncoder.encode("password123"),ADMINTRAINEE.getGrantedAuthorities(),
                         true,true,true,true)
         );
         return applicationUsers;
    }
}
