package com.example;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class AppTest {

    @Test
    void factorialBaseCases() {
        assertEquals(1, App.factorial(0));
        assertEquals(1, App.factorial(1));
    }

    @Test
    void factorialKnownValues() {
        assertEquals(120, App.factorial(5));
        assertEquals(3628800, App.factorial(10));
    }

    @Test
    void factorialRejectsNegative() {
        assertThrows(IllegalArgumentException.class, () -> App.factorial(-1));
    }
}
