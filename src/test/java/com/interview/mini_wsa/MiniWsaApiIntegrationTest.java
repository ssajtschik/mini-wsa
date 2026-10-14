package com.interview.mini_wsa;

import com.interview.mini_wsa.exception.GlobalExceptionHandler;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureRestTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.client.RestTestClient;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end tests over real HTTP: controller, service, JPA and a Testcontainers PostgreSQL.
 * Data is committed, so every test works on its own configId and client IPs to stay independent.
 * Threat scores follow application.yaml: severity + action + 15 for /admin or /login, plus 15 once
 * the same client IP sent 5 events within 10 minutes.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureRestTestClient
@Import(TestcontainersConfiguration.class)
@Testcontainers(disabledWithoutDocker = true)
class MiniWsaApiIntegrationTest {

    private static final String FROM = "2026-10-12T00:00:00Z";
    private static final String TO = "2026-10-12T23:59:59Z";

    private static final AtomicLong CONFIG_IDS = new AtomicLong(700_000);
    private static final AtomicInteger IP_SUFFIX = new AtomicInteger(1);
    private static final AtomicInteger EVENT_IDS = new AtomicInteger();

    @Autowired
    private RestTestClient client;

    // --- ingest ---

    @Test
    void ingestSingleEvent_isEnrichedAndReturnedBySamples() {
        long configId = CONFIG_IDS.incrementAndGet();
        String ip = nextIp();

        ingest("{\"event\": " + event("evt-single-" + configId, configId, "2026-10-12T10:00:00Z",
                ip, "/api/v1/login", "CRITICAL", "INJECTION", "DENY") + "}")
                .expectStatus().isCreated();

        samples("configId=" + configId)
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.content.length()").isEqualTo(1)
                .jsonPath("$.content[0].eventId").isEqualTo("evt-single-" + configId)
                .jsonPath("$.content[0].configId").isEqualTo(configId)
                .jsonPath("$.content[0].clientIp").isEqualTo(ip)
                .jsonPath("$.content[0].action").isEqualTo("DENY")
                .jsonPath("$.content[0].rule.category").isEqualTo("INJECTION")
                .jsonPath("$.content[0].rule.severity").isEqualTo("CRITICAL")
                .jsonPath("$.content[0].receivedAt").exists()
                // CRITICAL (40) + DENY (20) + sensitive path (15)
                .jsonPath("$.content[0].threatScore").isEqualTo(75);
    }

    @Test
    void ingestBatch_feedsSummaryAggregates() {
        long configId = CONFIG_IDS.incrementAndGet();
        String attacker = nextIp();
        String other = nextIp();

        ingest("{\"events\": [" + String.join(",",
                // CRITICAL (40) + DENY (20) + /login (15) = 75
                event(nextEventId(), configId, "2026-10-12T01:00:00Z", attacker, "/login", "CRITICAL", "INJECTION", "DENY"),
                // HIGH (30) + DENY (20) + /login (15) = 65
                event(nextEventId(), configId, "2026-10-12T02:00:00Z", attacker, "/login", "HIGH", "INJECTION", "DENY"),
                // MEDIUM (20) + ALERT (10) = 30
                event(nextEventId(), configId, "2026-10-12T03:00:00Z", other, "/search", "MEDIUM", "XSS", "ALERT"),
                // LOW (10) + MONITOR (0) + /login (15) = 25
                event(nextEventId(), configId, "2026-10-12T04:00:00Z", attacker, "/login", "LOW", "BOT", "MONITOR"),
                // outside the queried range
                event(nextEventId(), configId, "2026-10-13T04:00:00Z", other, "/search", "LOW", "BOT", "DENY"))
                + "]}")
                .expectStatus().isCreated();

        summary(configId)
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.configId").isEqualTo(configId)
                .jsonPath("$.timeRange.from").exists()
                .jsonPath("$.timeRange.to").exists()
                .jsonPath("$.totalEvents").isEqualTo(4)
                .jsonPath("$.byCategory.INJECTION.count").isEqualTo(2)
                .jsonPath("$.byCategory.INJECTION.avgThreatScore").isEqualTo(70.0)
                .jsonPath("$.byCategory.XSS.count").isEqualTo(1)
                .jsonPath("$.byCategory.BOT.avgThreatScore").isEqualTo(25.0)
                .jsonPath("$.byAction.DENY").isEqualTo(2)
                .jsonPath("$.byAction.ALERT").isEqualTo(1)
                .jsonPath("$.byAction.MONITOR").isEqualTo(1)
                .jsonPath("$.topAttackers.length()").isEqualTo(2)
                .jsonPath("$.topAttackers[0].clientIp").isEqualTo(attacker)
                .jsonPath("$.topAttackers[0].count").isEqualTo(3)
                .jsonPath("$.topAttackers[0].avgThreatScore").isEqualTo(55.0)
                .jsonPath("$.topAttackers[1].clientIp").isEqualTo(other)
                .jsonPath("$.topTargetedPaths[0].path").isEqualTo("/login")
                .jsonPath("$.topTargetedPaths[0].count").isEqualTo(3)
                .jsonPath("$.topTargetedPaths[1].path").isEqualTo("/search")
                .jsonPath("$.topTargetedPaths[1].count").isEqualTo(1);
    }

    @Test
    void ingest_repeatedClientIp_triggersWindowedRuleScore() {
        long configId = CONFIG_IDS.incrementAndGet();
        String ip = nextIp();

        // The rule counts already stored events, so the 6th request is the first to see 5 prior hits
        for (int i = 0; i < 6; i++) {
            ingest("{\"event\": " + event("evt-rule-" + configId + "-" + i, configId,
                    "2026-10-12T05:00:0" + i + "Z", ip, "/", "LOW", "BOT", "MONITOR") + "}")
                    .expectStatus().isCreated();
        }

        samples("configId=" + configId + "&limit=10")
                .expectStatus().isOk()
                .expectBody()
                // newest first: LOW (10) + MONITOR (0) + rule (15)
                .jsonPath("$.content[0].eventId").isEqualTo("evt-rule-" + configId + "-5")
                .jsonPath("$.content[0].threatScore").isEqualTo(25)
                .jsonPath("$.content[1].threatScore").isEqualTo(10)
                .jsonPath("$.content[5].threatScore").isEqualTo(10);
    }

    @Test
    void ingest_duplicateEventId_returnsConflictAndKeepsOriginal() {
        long configId = CONFIG_IDS.incrementAndGet();
        String body = "{\"event\": " + event("evt-dup-" + configId, configId, "2026-10-12T06:00:00Z",
                nextIp(), "/", "LOW", "XSS", "MONITOR") + "}";

        ingest(body).expectStatus().isCreated();
        ingest(body)
                .expectStatus().isEqualTo(409)
                .expectBody()
                .jsonPath("$.status").isEqualTo(409)
                .jsonPath("$.detail").isEqualTo(GlobalExceptionHandler.DUPLICATE_EVENT);

        summary(configId).expectStatus().isOk().expectBody().jsonPath("$.totalEvents").isEqualTo(1);
    }

    @Test
    void ingest_batchWithDuplicate_rollsBackWholeBatch() {
        long configId = CONFIG_IDS.incrementAndGet();
        String ip = nextIp();
        String duplicateId = "evt-batch-dup-" + configId;

        ingest("{\"event\": " + event(duplicateId, configId, "2026-10-12T06:00:00Z", ip, "/", "LOW", "XSS", "MONITOR") + "}")
                .expectStatus().isCreated();
        ingest("{\"events\": [" + String.join(",",
                event(nextEventId(), configId, "2026-10-12T07:00:00Z", ip, "/", "LOW", "XSS", "MONITOR"),
                event(duplicateId, configId, "2026-10-12T08:00:00Z", ip, "/", "LOW", "XSS", "MONITOR"))
                + "]}")
                .expectStatus().isEqualTo(409);

        summary(configId).expectStatus().isOk().expectBody().jsonPath("$.totalEvents").isEqualTo(1);
    }

    @Test
    void ingest_bothEventAndEvents_returnsBadRequest() {
        long configId = CONFIG_IDS.incrementAndGet();
        String event = event(nextEventId(), configId, "2026-10-12T06:00:00Z", nextIp(), "/", "LOW", "XSS", "MONITOR");

        ingest("{\"event\": " + event + ", \"events\": [" + event + "]}")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.detail").isEqualTo("Exactly one of 'event' or 'events' must be supplied, but both were present")
                .jsonPath("$.errors").doesNotExist();

        summary(configId).expectStatus().isOk().expectBody().jsonPath("$.totalEvents").isEqualTo(0);
    }

    @Test
    void ingest_emptyBody_returnsBadRequest() {
        ingest("{}")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.detail").isEqualTo("Exactly one of 'event' or 'events' must be supplied, but neither was present");
    }

    @Test
    void ingest_batchItemMissingRequiredField_returnsBadRequestNamingTheField() {
        long configId = CONFIG_IDS.incrementAndGet();
        String valid = event(nextEventId(), configId, "2026-10-12T06:00:00Z", nextIp(), "/", "LOW", "XSS", "MONITOR");
        String invalid = event(nextEventId(), configId, "2026-10-12T06:00:00Z", nextIp(), "/", "LOW", "XSS", "MONITOR")
                .replace("\"hostname\": \"www.example.com\",", "");

        ingest("{\"events\": [" + valid + "," + invalid + "]}")
                .expectStatus().isBadRequest()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.status").isEqualTo(400)
                .jsonPath("$.detail").isEqualTo("Invalid security event(s).")
                .jsonPath("$.errors").isEqualTo(List.of("events[1].hostname: must not be null"));

        summary(configId).expectStatus().isOk().expectBody().jsonPath("$.totalEvents").isEqualTo(0);
    }

    @Test
    void ingest_singleEventMissingRequiredField_returnsBadRequest() {
        long configId = CONFIG_IDS.incrementAndGet();
        String invalid = event(nextEventId(), configId, "2026-10-12T06:00:00Z", nextIp(), "/", "LOW", "XSS", "MONITOR")
                .replace("\"policyId\": \"pol-7\",", "");

        ingest("{\"event\": " + invalid + "}")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.detail").isEqualTo("Invalid request content.");
    }

    @Test
    void ingest_unknownAction_returnsBadRequest() {
        long configId = CONFIG_IDS.incrementAndGet();

        ingest("{\"event\": " + event(nextEventId(), configId, "2026-10-12T06:00:00Z", nextIp(), "/", "LOW", "XSS", "BLOCK") + "}")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.detail").isEqualTo("Failed to read request");
    }

    @Test
    void ingest_malformedJson_returnsBadRequestWithFixedMessage() {
        ingest("{\"event\": ")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.detail").isEqualTo("Failed to read request")
                .jsonPath("$.errors").doesNotExist();
    }

    // --- samples ---

    @Test
    void samples_filtersByCategoryActionAndTimeRange() {
        long configId = CONFIG_IDS.incrementAndGet();
        String ip = nextIp();
        ingest("{\"events\": [" + String.join(",",
                event("evt-f1-" + configId, configId, "2026-10-12T01:00:00Z", ip, "/", "HIGH", "INJECTION", "DENY"),
                event("evt-f2-" + configId, configId, "2026-10-12T02:00:00Z", ip, "/", "HIGH", "INJECTION", "ALERT"),
                event("evt-f3-" + configId, configId, "2026-10-12T03:00:00Z", ip, "/", "HIGH", "XSS", "DENY"),
                event("evt-f4-" + configId, configId, "2026-10-11T03:00:00Z", ip, "/", "HIGH", "INJECTION", "DENY"))
                + "]}")
                .expectStatus().isCreated();

        samples("configId=" + configId + "&category=INJECTION")
                .expectStatus().isOk()
                .expectBody().jsonPath("$.content.length()").isEqualTo(3);

        samples("configId=" + configId + "&category=INJECTION&action=DENY")
                .expectStatus().isOk()
                .expectBody().jsonPath("$.content.length()").isEqualTo(2);

        samples("configId=" + configId + "&category=INJECTION&action=DENY&from=" + FROM + "&to=" + TO)
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.content.length()").isEqualTo(1)
                .jsonPath("$.content[0].eventId").isEqualTo("evt-f1-" + configId);
    }

    @Test
    void samples_paginatesNewestFirst() {
        long configId = CONFIG_IDS.incrementAndGet();
        StringBuilder events = new StringBuilder();
        for (int i = 0; i < 5; i++) {
            if (i > 0) {
                events.append(',');
            }
            events.append(event("evt-p" + i + "-" + configId, configId, "2026-10-12T0" + i + ":00:00Z",
                    nextIp(), "/", "LOW", "XSS", "MONITOR"));
        }
        ingest("{\"events\": [" + events + "]}").expectStatus().isCreated();

        samples("configId=" + configId + "&limit=2&offset=0")
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.content.length()").isEqualTo(2)
                .jsonPath("$.content[0].eventId").isEqualTo("evt-p4-" + configId)
                .jsonPath("$.content[1].eventId").isEqualTo("evt-p3-" + configId)
                .jsonPath("$..totalElements").isEqualTo(5)
                .jsonPath("$..totalPages").isEqualTo(3);

        samples("configId=" + configId + "&limit=2&offset=4")
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.content.length()").isEqualTo(1)
                .jsonPath("$.content[0].eventId").isEqualTo("evt-p0-" + configId);
    }

    @Test
    void samples_unknownConfig_returnsEmptyPage() {
        samples("configId=" + CONFIG_IDS.incrementAndGet())
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.content.length()").isEqualTo(0)
                .jsonPath("$..totalElements").isEqualTo(0);
    }

    @Test
    void samples_offsetNotMultipleOfLimit_returnsBadRequest() {
        samples("limit=20&offset=15")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.detail").value(detail -> assertTrue(detail.toString().startsWith("Invalid offset (15)"), detail.toString()));
    }

    @Test
    void samples_limitAboveMaximum_returnsBadRequest() {
        samples("limit=101")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.detail").isEqualTo(GlobalExceptionHandler.VALIDATION_FAILED)
                .jsonPath("$.errors").isEqualTo(List.of("limit: must be less than or equal to 100"));
    }

    @Test
    void samples_unknownCategory_returnsBadRequest() {
        samples("category=NOT_A_CATEGORY")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.detail").isEqualTo("Unexpected value 'NOT_A_CATEGORY'");
    }

    @Test
    void samples_unparsableConfigId_returnsBadRequest() {
        samples("configId=abc")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.detail").isEqualTo("Failed to convert 'configId' with value: 'abc'");
    }

    // --- summary ---

    @Test
    void summary_unknownConfig_returnsZeroTotals() {
        summary(CONFIG_IDS.incrementAndGet())
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.totalEvents").isEqualTo(0)
                .jsonPath("$.byCategory").isEmpty()
                .jsonPath("$.byAction").isEmpty()
                .jsonPath("$.topAttackers").isEmpty()
                .jsonPath("$.topTargetedPaths").isEmpty();
    }

    private RestTestClient.ResponseSpec ingest(String body) {
        return client.post().uri("/v1/events/ingest")
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .exchange();
    }

    private RestTestClient.ResponseSpec samples(String query) {
        return client.get().uri("/v1/events/samples?" + query).exchange();
    }

    private RestTestClient.ResponseSpec summary(long configId) {
        return client.get()
                .uri("/v1/stats/summary?configId={configId}&from={from}&to={to}", configId, FROM, TO)
                .exchange();
    }

    private static String nextIp() {
        int n = IP_SUFFIX.getAndIncrement();
        return "10.0." + (n / 250) + "." + (n % 250 + 1);
    }

    private static String nextEventId() {
        return "evt-it-" + EVENT_IDS.incrementAndGet();
    }

    private static String event(String eventId, long configId, String timestamp, String clientIp, String path,
                                String severity, String category, String action) {
        return """
                {
                  "eventId": "%s",
                  "timestamp": "%s",
                  "configId": %d,
                  "policyId": "pol-7",
                  "clientIp": "%s",
                  "hostname": "www.example.com",
                  "path": "%s",
                  "rule": {"id": "950001", "severity": "%s", "category": "%s"},
                  "action": "%s"
                }
                """.formatted(eventId, timestamp, configId, clientIp, path, severity, category, action);
    }
}
