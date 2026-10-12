package com.interview.mini_wsa.repository;

import com.interview.mini_wsa.model.SecurityEventEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Runs against the PostgreSQL from compose.yaml (the query relies on Postgres types such as jsonb);
 * each test is rolled back by {@link DataJpaTest}.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class SecurityEventRepositoryTest {

    private static final long CONFIG_ID = 990001L;
    private static final OffsetDateTime FROM = OffsetDateTime.of(2026, 10, 12, 0, 0, 0, 0, ZoneOffset.UTC);
    private static final OffsetDateTime TO = OffsetDateTime.of(2026, 10, 12, 23, 59, 59, 0, ZoneOffset.UTC);

    @Autowired
    private SecurityEventRepository repository;

    private int sequence;

    @BeforeEach
    void setUp() {
        repository.saveAll(List.of(
                event(CONFIG_ID, "INJECTION", 80, FROM),
                event(CONFIG_ID, "INJECTION", 61, FROM.plusHours(5)),
                event(CONFIG_ID, "INJECTION", 70, TO),
                event(CONFIG_ID, "XSS", 40, FROM.plusHours(12)),
                // outside the range
                event(CONFIG_ID, "INJECTION", 10, FROM.minusSeconds(1)),
                event(CONFIG_ID, "XSS", 10, TO.plusSeconds(1)),
                // other configuration
                event(CONFIG_ID + 1, "INJECTION", 10, FROM.plusHours(1))));
        repository.flush();
    }

    @Test
    void findCategoryStats_groupsByCategoryWithinInclusiveRange() {
        Map<String, CategoryStats> stats = repository.findCategoryStats(CONFIG_ID, FROM, TO).stream()
                .collect(Collectors.toMap(CategoryStats::getCategory, s -> s));

        assertEquals(2, stats.size());
        assertEquals(3, stats.get("INJECTION").getCount());
        assertEquals(70.333, stats.get("INJECTION").getAvgThreatScore(), 0.001);
        assertEquals(1, stats.get("XSS").getCount());
        assertEquals(40.0, stats.get("XSS").getAvgThreatScore(), 0.001);
    }

    @Test
    void findCategoryStats_ordersByCountDescending() {
        List<CategoryStats> stats = repository.findCategoryStats(CONFIG_ID, FROM, TO);

        assertEquals(List.of("INJECTION", "XSS"), stats.stream().map(CategoryStats::getCategory).toList());
    }

    @Test
    void findCategoryStats_noEventsInRange_returnsEmpty() {
        assertTrue(repository.findCategoryStats(CONFIG_ID, TO.plusDays(1), TO.plusDays(2)).isEmpty());
    }

    private SecurityEventEntity event(long configId, String category, int threatScore, OffsetDateTime timestamp) {
        SecurityEventEntity entity = new SecurityEventEntity();
        entity.setEventId("repo-test-" + ++sequence);
        entity.setTimestamp(timestamp);
        entity.setReceivedAt(timestamp);
        entity.setConfigId(configId);
        entity.setPolicyId("pol-test");
        entity.setClientIp("203.0.113.42");
        entity.setHostname("www.example.com");
        entity.setPath("/");
        entity.setAction("DENY");
        entity.setAttackType(category);
        entity.setCategory(category);
        entity.setSeverity("HIGH");
        entity.setThreatScore(threatScore);
        entity.setRawPayload("{}");
        return entity;
    }
}
