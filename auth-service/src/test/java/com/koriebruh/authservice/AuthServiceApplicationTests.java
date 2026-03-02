package com.koriebruh.authservice;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Integration test that loads the full Spring ApplicationContext.
 * Requires PostgreSQL and Redis to be running.
 *
 * Run this test only when:
 * - Docker containers are up (docker-compose up)
 * - Or use TestContainers in CI/CD environment
 */
@SpringBootTest
class AuthServiceApplicationTests {

    @Test
    void contextLoads() {
    }

}
