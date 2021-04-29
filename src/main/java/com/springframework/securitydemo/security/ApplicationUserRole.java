package com.springframework.securitydemo.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.springframework.securitydemo.security.ApplicationUserPermission.*;

public enum     ApplicationUserRole {
        STUDENT(Sets.newHashSet()),
        ADMIN(Sets.newHashSet(COURSE_READ,COURSE_WRITE,STUDENT_READ,STUDENT_WRITE )),
        ADMINTRAINEE(Sets.newHashSet(COURSE_READ,STUDENT_READ));

    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {

        return permissions;
    }

    //this class is like a conversion of class ApplicationUserPermission (an enum type that has been declared)
    // to SimpleGrantedAuthority
    public Set <SimpleGrantedAuthority> getGrantedAuthorities(){
        Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
        permissions.add(new SimpleGrantedAuthority("ROLE_"+this.name()));
        return permissions;

    }
}
