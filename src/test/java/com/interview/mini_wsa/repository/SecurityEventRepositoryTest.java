package com.interview.mini_wsa.repository;

import com.interview.mini_wsa.TestcontainersConfiguration;
import com.interview.mini_wsa.model.Rule;
import com.interview.mini_wsa.model.SecurityAction;
import com.interview.mini_wsa.model.SecurityEventEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Runs against a Testcontainers PostgreSQL (the schema relies on Postgres types such as jsonb);
 * each test is rolled back by {@link DataJpaTest}.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(TestcontainersConfiguration.class)
@Testcontainers(disabledWithoutDocker = true)
class SecurityEventRepositoryTest {

    private static final long CONFIG_ID = 990001L;
    private static final OffsetDateTime FROM = OffsetDateTime.of(2026, 10, 12, 0, 0, 0, 0, ZoneOffset.UTC);
    private static final OffsetDateTime TO = OffsetDateTime.of(2026, 10, 12, 23, 59, 59, 0, ZoneOffset.UTC);
    private static final String IP_A = "203.0.113.42";
    private static final String IP_B = "198.51.100.7";

    @Autowired
    private SecurityEventRepository repository;

    private int sequence;

    @BeforeEach
    void setUp() {
        repository.saveAll(List.of(
                event(CONFIG_ID, "INJECTION", SecurityAction.DENY, 80, IP_A, "/login", FROM),
                event(CONFIG_ID, "INJECTION", SecurityAction.DENY, 61, IP_A, "/login", FROM.plusHours(5)),
                event(CONFIG_ID, "INJECTION", SecurityAction.ALERT, 70, IP_B, "/admin", TO),
                event(CONFIG_ID, "XSS", SecurityAction.MONITOR, 40, IP_A, "/login", FROM.plusHours(12)),
                // outside the range
                event(CONFIG_ID, "INJECTION", SecurityAction.DENY, 10, IP_B, "/admin", FROM.minusSeconds(1)),
                event(CONFIG_ID, "XSS", SecurityAction.DENY, 10, IP_B, "/admin", TO.plusSeconds(1)),
                // other configuration
                event(CONFIG_ID + 1, "INJECTION", SecurityAction.DENY, 10, IP_A, "/login", FROM.plusHours(1))));
        repository.flush();
    }

    // --- summary queries ---

    @Test
    void countByConfigIdAndTimestampBetween_countsInclusiveRangeOfOneConfig() {
        assertEquals(4, repository.countByConfigIdAndTimestampBetween(CONFIG_ID, FROM, TO));
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

    @Test
    void findActionStats_groupsByActionWithMostFrequentFirst() {
        List<ActionStats> stats = repository.findActionStats(CONFIG_ID, FROM, TO);

        Map<String, Long> counts = stats.stream().collect(Collectors.toMap(ActionStats::getAction, ActionStats::getCount));
        assertEquals(Map.of("DENY", 2L, "ALERT", 1L, "MONITOR", 1L), counts);
        assertEquals("DENY", stats.getFirst().getAction());
    }

    @Test
    void findTopAttackerStats_groupsByClientIpWithMostFrequentFirst() {
        List<AttackerStats> stats = repository.findTopAttackerStats(CONFIG_ID, FROM, TO);

        assertEquals(List.of(IP_A, IP_B), stats.stream().map(AttackerStats::getClientIp).toList());
        assertEquals(3, stats.get(0).getCount());
        assertEquals(60.333, stats.get(0).getAvgThreatScore(), 0.001);
        assertEquals(1, stats.get(1).getCount());
        assertEquals(70.0, stats.get(1).getAvgThreatScore(), 0.001);
    }

    @Test
    void findTopAttackerStats_isLimitedToTen() {
        long otherConfig = CONFIG_ID + 2;
        repository.saveAll(IntStream.range(0, 12)
                .mapToObj(i -> event(otherConfig, "BOT", SecurityAction.DENY, 10, "192.0.2." + i, "/", FROM))
                .toList());

        assertEquals(10, repository.findTopAttackerStats(otherConfig, FROM, TO).size());
    }

    @Test
    void findTopPathStats_groupsByPathWithMostFrequentFirst() {
        List<PathStats> stats = repository.findTopPathStats(CONFIG_ID, FROM, TO);

        assertEquals(List.of("/login", "/admin"), stats.stream().map(PathStats::getPath).toList());
        assertEquals(List.of(3L, 1L), stats.stream().map(PathStats::getCount).toList());
    }

    @Test
    void findTopPathStats_isLimitedToTen() {
        long otherConfig = CONFIG_ID + 2;
        repository.saveAll(IntStream.range(0, 12)
                .mapToObj(i -> event(otherConfig, "BOT", SecurityAction.DENY, 10, IP_A, "/path-" + i, FROM))
                .toList());

        assertEquals(10, repository.findTopPathStats(otherConfig, FROM, TO).size());
    }

    // --- filterEvents specification ---

    @Test
    void filterEvents_byConfigAndRange_returnsOnlyMatchingEvents() {
        List<SecurityEventEntity> events = repository.findAll(
                SecurityEventSpecs.filterEvents(CONFIG_ID, null, null, FROM, TO));

        assertEquals(4, events.size());
        assertTrue(events.stream().allMatch(e -> e.getConfigId() == CONFIG_ID));
    }

    @Test
    void filterEvents_withoutFilters_returnsEverything() {
        assertEquals(7, repository.findAll(SecurityEventSpecs.filterEvents(null, null, null, null, null)).size());
    }

    @Test
    void filterEvents_byCategory() {
        List<SecurityEventEntity> events = repository.findAll(
                SecurityEventSpecs.filterEvents(CONFIG_ID, "XSS", null, FROM, TO));

        assertEquals(1, events.size());
        assertEquals(Rule.CategoryEnum.XSS, events.getFirst().getCategory());
    }

    @Test
    void filterEvents_byAction() {
        List<SecurityEventEntity> events = repository.findAll(
                SecurityEventSpecs.filterEvents(CONFIG_ID, null, "DENY", FROM, TO));

        assertEquals(2, events.size());
        assertTrue(events.stream().allMatch(e -> e.getAction() == SecurityAction.DENY));
    }

    @Test
    void filterEvents_byCategoryAndAction() {
        List<SecurityEventEntity> events = repository.findAll(
                SecurityEventSpecs.filterEvents(CONFIG_ID, "INJECTION", "ALERT", FROM, TO));

        assertEquals(1, events.size());
        assertEquals(IP_B, events.getFirst().getClientIp());
    }

    @Test
    void filterEvents_blankFilters_areIgnored() {
        assertEquals(4, repository.findAll(SecurityEventSpecs.filterEvents(CONFIG_ID, " ", "", FROM, TO)).size());
    }

    @Test
    void filterEvents_rangeIsInclusiveOnEventTimestamp() {
        List<SecurityEventEntity> events = repository.findAll(
                SecurityEventSpecs.filterEvents(CONFIG_ID, null, null, TO, TO));

        assertEquals(1, events.size());
        assertEquals(TO, events.getFirst().getTimestamp().withOffsetSameInstant(ZoneOffset.UTC));
    }

    @Test
    void filterEvents_unknownCategory_throws() {
        assertThrows(IllegalArgumentException.class,
                () -> SecurityEventSpecs.filterEvents(CONFIG_ID, "NOT_A_CATEGORY", null, null, null));
    }

    @Test
    void filterEvents_unknownAction_throws() {
        assertThrows(IllegalArgumentException.class,
                () -> SecurityEventSpecs.filterEvents(CONFIG_ID, null, "BLOCK", null, null));
    }

    @Test
    void filterEvents_paged_returnsNewestFirstWithTotals() {
        Page<SecurityEventEntity> page = repository.findAll(
                SecurityEventSpecs.filterEvents(CONFIG_ID, null, null, FROM, TO),
                PageRequest.of(0, 2, Sort.by("timestamp").descending()));

        assertEquals(4, page.getTotalElements());
        assertEquals(2, page.getTotalPages());
        assertEquals(List.of(TO, FROM.plusHours(12)), page.getContent().stream()
                .map(e -> e.getTimestamp().withOffsetSameInstant(ZoneOffset.UTC)).toList());
    }

    // --- countMatchingField specification ---

    @Test
    void countMatchingField_countsEventsWithValueReceivedWithinWindow() {
        OffsetDateTime now = OffsetDateTime.now();
        String ip = "192.0.2.200";
        repository.saveAll(List.of(
                received(event(CONFIG_ID, "BOT", SecurityAction.DENY, 10, ip, "/", now), now),
                received(event(CONFIG_ID, "BOT", SecurityAction.DENY, 10, ip, "/", now), now.minusMinutes(5)),
                received(event(CONFIG_ID, "BOT", SecurityAction.DENY, 10, ip, "/", now), now.minusHours(1)),
                // other value
                received(event(CONFIG_ID, "BOT", SecurityAction.DENY, 10, "192.0.2.201", "/", now), now)));

        assertEquals(2, repository.count(SecurityEventSpecs.countMatchingField("clientIp", ip, 10)));
        assertEquals(3, repository.count(SecurityEventSpecs.countMatchingField("clientIp", ip, 120)));
    }

    @Test
    void countMatchingField_nullValue_countsAllEventsWithinWindow() {
        long before = repository.count(SecurityEventSpecs.countMatchingField("clientIp", null, 10));
        OffsetDateTime now = OffsetDateTime.now();
        repository.saveAll(List.of(
                received(event(CONFIG_ID, "BOT", SecurityAction.DENY, 10, "192.0.2.210", "/", now), now),
                received(event(CONFIG_ID, "BOT", SecurityAction.DENY, 10, "192.0.2.211", "/", now), now)));

        assertEquals(before + 2, repository.count(SecurityEventSpecs.countMatchingField("clientIp", null, 10)));
    }

    // --- constraints ---

    @Test
    void saveAndFlush_duplicateEventId_violatesUniqueConstraint() {
        SecurityEventEntity duplicate = event(CONFIG_ID, "BOT", SecurityAction.DENY, 10, IP_A, "/", FROM);
        duplicate.setEventId("repo-test-1");

        assertThrows(DataIntegrityViolationException.class, () -> repository.saveAndFlush(duplicate));
    }

    private static SecurityEventEntity received(SecurityEventEntity entity, OffsetDateTime receivedAt) {
        entity.setReceivedAt(receivedAt);
        return entity;
    }

    private SecurityEventEntity event(long configId, String category, SecurityAction action, int threatScore,
                                      String clientIp, String path, OffsetDateTime timestamp) {
        SecurityEventEntity entity = new SecurityEventEntity();
        entity.setEventId("repo-test-" + ++sequence);
        entity.setTimestamp(timestamp);
        entity.setReceivedAt(timestamp);
        entity.setConfigId(configId);
        entity.setPolicyId("pol-test");
        entity.setClientIp(clientIp);
        entity.setHostname("www.example.com");
        entity.setPath(path);
        entity.setAction(action);
        entity.setAttackType(category);
        entity.setCategory(Rule.CategoryEnum.fromValue(category));
        entity.setSeverity(Rule.SeverityEnum.HIGH);
        entity.setThreatScore(threatScore);
        entity.setRawPayload("{}");
        return entity;
    }
}
