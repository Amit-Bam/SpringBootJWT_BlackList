package com.example.jwt_basics1;

import com.example.jwt_basics1.entity.Role;
import com.example.jwt_basics1.entity.User;
import com.example.jwt_basics1.repository.RoleRepository;
import com.example.jwt_basics1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
// Lombok will generate a constructor with all the required fields, for autowiring
@RequiredArgsConstructor
// command line runner interface is used to run the code when the application starts
public class DataLoader implements CommandLineRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        // check if the database is empty
        if (userRepository.count() > 0) {
            return;
        }
        // else, populate the database with some data,create roles, admin and user, and save them to the database
        Role adminRole = new Role();
        adminRole.setRoleName("ADMIN");
        roleRepository.save(adminRole);

        Role userRole = new Role();
        userRole.setRoleName("USER");
        roleRepository.save(userRole);

        // create an admin user with an admin role and save it to the database
        User adminUser = new User();
        adminUser.setUsername("admin");
        // encode the password
        adminUser.setPassword(passwordEncoder.encode("admin"));
        List<Role> roles = new ArrayList<>();
        roles.add(adminRole);
        roles.add(userRole);
        adminUser.setRoles(roles);
        userRepository.save(adminUser);

        // create a user with a user role and save it to the database
        User user = new User();
        user.setUsername("user");
        // encode the password
        user.setPassword(passwordEncoder.encode("user"));
        List<Role> userRoles = new ArrayList<>();
        userRoles.add(userRole);
        user.setRoles(userRoles);
        userRepository.save(user);
    }
}