package com.contrast.frontgateservice.controller;

import com.contrast.frontgateservice.entity.User;
import com.contrast.frontgateservice.service.DataServiceProxy;
import com.contrast.frontgateservice.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@SpringBootTest
@AutoConfigureMockMvc
public class ApiControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DataServiceProxy dataServiceProxy;

    @MockBean
    private UserService userService;

    private User testUser;

    @BeforeEach
    public void setup() {
        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        testUser.setPassword("password");
        testUser.setEnabled(true);
    }

    @Test
    @WithMockUser(username = "testuser")
    public void testImportAddresses_WithValidData_ShouldSucceed() throws Exception {
        when(userService.findByUsername("testuser")).thenReturn(testUser);
        when(dataServiceProxy.createAddress(any())).thenReturn(ResponseEntity.ok("{}"));

        List<Map<String, Object>> addresses = new ArrayList<>();
        Map<String, Object> address = new HashMap<>();
        address.put("street", "123 Main St");
        address.put("city", "Springfield");
        addresses.add(address);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(addresses);
        oos.close();

        MockMultipartFile file = new MockMultipartFile(
                "file",
                "addresses.ser",
                "application/octet-stream",
                baos.toByteArray()
        );

        mockMvc.perform(multipart("/api/addresses/import")
                        .file(file))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.saved").value(1));
    }

    @Test
    @WithMockUser(username = "testuser")
    public void testImportAddresses_WithMaliciousClass_ShouldReject() throws Exception {
        when(userService.findByUsername("testuser")).thenReturn(testUser);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(new MaliciousPayload());
        oos.close();

        MockMultipartFile file = new MockMultipartFile(
                "file",
                "malicious.ser",
                "application/octet-stream",
                baos.toByteArray()
        );

        mockMvc.perform(multipart("/api/addresses/import")
                        .file(file))
                .andExpect(status().is5xxServerError());
    }

    @Test
    @WithMockUser(username = "testuser")
    public void testImportAddresses_WithEmptyFile_ShouldReturnBadRequest() throws Exception {
        MockMultipartFile emptyFile = new MockMultipartFile(
                "file",
                "empty.ser",
                "application/octet-stream",
                new byte[0]
        );

        mockMvc.perform(multipart("/api/addresses/import")
                        .file(emptyFile))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("No file provided"));
    }

    private static class MaliciousPayload implements java.io.Serializable {
        private static final long serialVersionUID = 1L;
        
        private void readObject(java.io.ObjectInputStream in) throws Exception {
            in.defaultReadObject();
        }
    }
}
