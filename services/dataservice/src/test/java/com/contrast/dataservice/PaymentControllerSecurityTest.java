package com.contrast.dataservice;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@SpringBootTest
class PaymentControllerSecurityTest {

    @Autowired
    private PaymentController paymentController;

    @MockBean
    private JdbcTemplate jdbcTemplate;

    @MockBean
    @Qualifier("creditCardsJdbcTemplate")
    private JdbcTemplate creditCardsJdbcTemplate;

    @Test
    void testSqlInjectionPrevention_CreditCardParameter() {
        String maliciousInput = "1234'); DROP TABLE credit_card; --";
        String validShipmentId = "123";

        when(creditCardsJdbcTemplate.update(anyString(), any(), any())).thenReturn(1);
        when(jdbcTemplate.update(anyString(), any(), any())).thenReturn(1);

        List<Map<String, Object>> result = paymentController.executeRawQuery(maliciousInput, validShipmentId);

        assertNotNull(result);
        assertEquals(1, result.size());
        assertTrue((Boolean) result.get(0).get("success"));

        verify(creditCardsJdbcTemplate).update(
            eq("INSERT INTO credit_card (card_number, shipment_id) VALUES (?, ?)"),
            eq(maliciousInput),
            eq(123L)
        );
    }

    @Test
    void testSqlInjectionPrevention_ShipmentIdParameter() {
        String validCreditCard = "4111111111111111";
        String maliciousShipmentId = "123 OR 1=1";

        List<Map<String, Object>> result = paymentController.executeRawQuery(validCreditCard, maliciousShipmentId);

        assertNotNull(result);
        assertEquals(1, result.size());
        assertTrue((Boolean) result.get(0).get("error"));
        assertEquals("Invalid shipment ID format", result.get(0).get("message"));

        verify(creditCardsJdbcTemplate, never()).update(anyString(), any(), any());
        verify(jdbcTemplate, never()).update(anyString(), any(), any());
    }

    @Test
    void testValidInput() {
        String validCreditCard = "4111111111111111";
        String validShipmentId = "456";

        when(creditCardsJdbcTemplate.update(anyString(), any(), any())).thenReturn(1);
        when(jdbcTemplate.update(anyString(), any(), any())).thenReturn(1);

        List<Map<String, Object>> result = paymentController.executeRawQuery(validCreditCard, validShipmentId);

        assertNotNull(result);
        assertEquals(1, result.size());
        assertTrue((Boolean) result.get(0).get("success"));
        assertEquals(456L, result.get(0).get("shipment_id"));

        verify(creditCardsJdbcTemplate).update(
            eq("INSERT INTO credit_card (card_number, shipment_id) VALUES (?, ?)"),
            eq(validCreditCard),
            eq(456L)
        );
        verify(jdbcTemplate).update(
            eq("UPDATE shipment SET credit_card = ? WHERE id = ?"),
            eq("XXXX-XXXX-XXXX-1111"),
            eq(456L)
        );
    }

    @Test
    void testInvalidShipmentIdFormat() {
        String validCreditCard = "4111111111111111";
        String invalidShipmentId = "abc";

        List<Map<String, Object>> result = paymentController.executeRawQuery(validCreditCard, invalidShipmentId);

        assertNotNull(result);
        assertEquals(1, result.size());
        assertTrue((Boolean) result.get(0).get("error"));
        assertEquals("Invalid shipment ID format", result.get(0).get("message"));
    }

    @Test
    void testMissingParameters() {
        List<Map<String, Object>> result = paymentController.executeRawQuery(null, null);

        assertNotNull(result);
        assertEquals(1, result.size());
        assertTrue((Boolean) result.get(0).get("error"));
        assertEquals("Both creditCard and shipmentId parameters are required for payment processing", 
                     result.get(0).get("message"));
    }
}
