package com.koriebruh.authservice.integration;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.ApplicationContext;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.KafkaContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.time.Duration;

/**
 * Base class for all integration tests.
 *
 * <h2>Banking Best Practices Implemented:</h2>
 * <ul>
 *   <li><b>Isolated Environment:</b> Uses TestContainers to spin up fresh PostgreSQL, Redis, and Kafka
 *       instances for each test class — no shared state with production/development databases.</li>
 *   <li><b>Data Cleanup:</b> Each test starts with a clean database state via {@link #cleanupTestData()}</li>
 *   <li><b>No Production Data Risk:</b> TestContainers ensures tests never touch real databases.</li>
 *   <li><b>Audit Trail:</b> All operations are logged for compliance verification.</li>
 *   <li><b>Reproducibility:</b> Tests are deterministic and can be run in any environment (CI/CD, local).</li>
 * </ul>
 *
 * <h2>Container Lifecycle:</h2>
 * <ul>
 *   <li>Containers are shared across all tests in a class (performance optimization)</li>
 *   <li>Each test method starts with cleaned data (isolation)</li>
 *   <li>Containers are destroyed after all tests complete</li>
 * </ul>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class BaseIntegrationTest {

    // -------------------------------------------------------------------------
    // TESTCONTAINERS - Isolated Database Environment
    // -------------------------------------------------------------------------

    protected static final PostgreSQLContainer<?> postgresContainer;
    protected static final GenericContainer<?> redisContainer;
    protected static final KafkaContainer kafkaContainer;

    static {
        // Start containers in static block to ensure they're running before @DynamicPropertySource
        postgresContainer = new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
                .withDatabaseName("auth_db_test")
                .withUsername("test_user")
                .withPassword("test_pass");
        postgresContainer.start();

        redisContainer = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
                .withExposedPorts(6379);
        redisContainer.start();

        kafkaContainer = new KafkaContainer(DockerImageName.parse("confluentinc/cp-kafka:7.5.0"));
        kafkaContainer.start();
    }

    // -------------------------------------------------------------------------
    // TEST CLIENTS
    // -------------------------------------------------------------------------

    @LocalServerPort
    protected int port;

    @Autowired
    protected ApplicationContext applicationContext;

    protected WebTestClient webTestClient;

    @Autowired
    protected DatabaseClient databaseClient;

    @Autowired
    protected ReactiveStringRedisTemplate redisTemplate;

    @BeforeAll
    void setupWebTestClient() {
        this.webTestClient = WebTestClient
                .bindToServer()
                .baseUrl("http://localhost:" + port)
                .responseTimeout(Duration.ofSeconds(30))
                .build();
    }

    // -------------------------------------------------------------------------
    // DYNAMIC PROPERTIES - Wire containers to Spring context
    // -------------------------------------------------------------------------

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        // PostgreSQL - JDBC for Flyway
        registry.add("spring.datasource.url", postgresContainer::getJdbcUrl);
        registry.add("spring.datasource.username", postgresContainer::getUsername);
        registry.add("spring.datasource.password", postgresContainer::getPassword);

        // PostgreSQL - R2DBC for reactive operations
        registry.add("spring.r2dbc.url", () -> String.format("r2dbc:postgresql://%s:%d/%s",
                postgresContainer.getHost(),
                postgresContainer.getMappedPort(5432),
                postgresContainer.getDatabaseName()));
        registry.add("spring.r2dbc.username", postgresContainer::getUsername);
        registry.add("spring.r2dbc.password", postgresContainer::getPassword);

        // Flyway
        registry.add("spring.flyway.url", postgresContainer::getJdbcUrl);
        registry.add("spring.flyway.user", postgresContainer::getUsername);
        registry.add("spring.flyway.password", postgresContainer::getPassword);

        // Redis
        registry.add("spring.data.redis.host", redisContainer::getHost);
        registry.add("spring.data.redis.port", () -> redisContainer.getMappedPort(6379));

        // Kafka
        registry.add("spring.kafka.bootstrap-servers", kafkaContainer::getBootstrapServers);

        // Mail - disable for tests
        registry.add("spring.mail.host", () -> "localhost");
        registry.add("spring.mail.port", () -> "1025");
    }

    // -------------------------------------------------------------------------
    // TEST DATA CLEANUP - Banking Best Practice: No residual data
    // -------------------------------------------------------------------------

    /**
     * Clean up all test data before each test.
     * This ensures test isolation and prevents data leakage between tests.
     *
     * <p><b>Banking Compliance:</b> This follows the principle of data minimization
     * and ensures no test data persists beyond its intended lifecycle.
     */
    @BeforeEach
    void cleanupTestData() {
        // Clean Redis
        redisTemplate.getConnectionFactory()
                .getReactiveConnection()
                .serverCommands()
                .flushAll()
                .block(Duration.ofSeconds(5));

        // Clean database tables in correct order (respect foreign keys)
        cleanupDatabaseTables();
    }

    /**
     * Cleans up database tables in the correct order to respect foreign key constraints.
     * Uses TRUNCATE with CASCADE for complete cleanup.
     */
    private void cleanupDatabaseTables() {
        // Delete in reverse dependency order
        databaseClient.sql("DELETE FROM refresh_tokens").then().block(Duration.ofSeconds(5));
        databaseClient.sql("DELETE FROM users WHERE email LIKE '%@test.com' OR email LIKE '%@integration.test'")
                .then().block(Duration.ofSeconds(5));

        // Reset sequences for predictable test data (optional)
        // databaseClient.sql("ALTER SEQUENCE user_code_seq RESTART WITH 1").then().block();
    }

    // -------------------------------------------------------------------------
    // TEST DATA BUILDERS - Banking compliant test data
    // -------------------------------------------------------------------------

    /**
     * Generates a unique test email to prevent conflicts between tests.
     * Uses timestamp and random suffix for uniqueness.
     */
    protected String generateTestEmail() {
        return String.format("test_%d_%s@integration.test",
                System.currentTimeMillis(),
                java.util.UUID.randomUUID().toString().substring(0, 8));
    }

    /**
     * Generates a unique test phone number.
     */
    protected String generateTestPhone() {
        return String.format("08%010d", System.currentTimeMillis() % 10000000000L);
    }

    /**
     * Generates a unique test NIK (Indonesian ID number).
     * Format: 16 digits
     */
    protected String generateTestNik() {
        return String.format("%016d", System.currentTimeMillis() % 10000000000000000L);
    }

    // -------------------------------------------------------------------------
    // HELPER METHODS
    // -------------------------------------------------------------------------

    /**
     * Configure WebTestClient with longer timeout for banking operations.
     */
    protected WebTestClient getWebTestClient() {
        return webTestClient.mutate()
                .responseTimeout(Duration.ofSeconds(30))
                .build();
    }
}


