package com.interview.mini_wsa;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Starts a throwaway PostgreSQL (same image as compose.yaml) and wires it into the datasource via
 * {@link ServiceConnection}, so DB-backed tests do not depend on a locally running database.
 * The container is shared by every test context that imports this configuration.
 *
 * <p>Pair with {@code @Testcontainers(disabledWithoutDocker = true)} so these tests are skipped,
 * rather than failing the build, on machines without Docker.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfiguration {

    @Bean
    @ServiceConnection
    PostgreSQLContainer postgresContainer() {
        return new PostgreSQLContainer("postgres:18-alpine");
    }
}
