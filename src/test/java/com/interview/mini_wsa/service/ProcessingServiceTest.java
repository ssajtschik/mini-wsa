package com.interview.mini_wsa.service;

import com.akamai.wsa.model.IngestRequest;
import com.akamai.wsa.model.Rule;
import com.akamai.wsa.model.SecurityEvent;
import com.interview.mini_wsa.configuration.WsaConfig;
import com.interview.mini_wsa.exception.InvalidIngestRequestException;
import com.interview.mini_wsa.model.SecurityEventEntity;
import com.interview.mini_wsa.repository.SecurityEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class ProcessingServiceTest {

    private static final OffsetDateTime EVENT_TIME = OffsetDateTime.of(2026, 5, 20, 14, 32, 10, 0, ZoneOffset.UTC);

    @Mock
    private SecurityEventRepository securityEventRepository;

    @Captor
    private ArgumentCaptor<List<SecurityEventEntity>> entitiesCaptor;

    private final JsonMapper jsonMapper = JsonMapper.builder().build();

    private WsaConfig wsaConfig;
    private ProcessingService processingService;

    @BeforeEach
    void setUp() {
        wsaConfig = new WsaConfig();
        wsaConfig.setCategories(new HashMap<>(Map.of(
                "INJECTION", "SQL/Command Injection",
                "XSS", "Cross-Site Scripting")));
        wsaConfig.setSeverities(new HashMap<>(Map.of(
                "CRITICAL", 40,
                "HIGH", 30,
                "MEDIUM", 20,
                "LOW", 10)));
        wsaConfig.setActions(new HashMap<>(Map.of(
                "DENY", 20,
                "ALERT", 10,
                "MONITOR", 0)));
        wsaConfig.setSensitivePaths(List.of("/admin", "/login"));
        wsaConfig.setRules(new ArrayList<>()); // TODO: Not implemented yet

        processingService = new ProcessingServiceImpl(wsaConfig, securityEventRepository, jsonMapper);
    }

    @Test
    void ingest_singleEvent_mapsAndPersistsEntity() {
        SecurityEvent event = event("evt-00132", "/api/v1/login",
                Rule.SeverityEnum.CRITICAL, Rule.CategoryEnum.INJECTION, SecurityEvent.ActionEnum.DENY);
        event.getRule()
                .putAdditionalProperty("ruleId", "950001")
                .putAdditionalProperty("name", "SQL Injection Attack")
                .putAdditionalProperty("message", "SQLi detected in query string");

        OffsetDateTime before = OffsetDateTime.now();
        processingService.ingest(new IngestRequest().event(event));
        OffsetDateTime after = OffsetDateTime.now();

        verify(securityEventRepository).saveAll(entitiesCaptor.capture());
        List<SecurityEventEntity> saved = entitiesCaptor.getValue();
        assertEquals(1, saved.size());

        SecurityEventEntity entity = saved.getFirst();
        assertEquals("evt-00132", entity.getEventId());
        assertEquals(EVENT_TIME, entity.getTimestamp());
        assertEquals(14227L, entity.getConfigId());
        assertEquals("pol-7", entity.getPolicyId());
        assertFalse(entity.getReceivedAt().isBefore(before));
        assertFalse(entity.getReceivedAt().isAfter(after));
        assertEquals("203.0.113.42", entity.getClientIp());
        assertEquals("www.example.com", entity.getHostname());
        assertEquals("/api/v1/login", entity.getPath());
        assertEquals("DENY", entity.getAction());
        assertEquals("CRITICAL", entity.getRule().getSeverity());
        assertEquals("INJECTION", entity.getRule().getCategory());
        assertEquals("950001", entity.getRule().getRuleId());
        assertEquals("SQL Injection Attack", entity.getRule().getName());
        assertEquals("SQLi detected in query string", entity.getRule().getMessage());
        assertEquals("SQL/Command Injection", entity.getAttackType());
        // CRITICAL (40) + DENY (20) + sensitive path (15)
        assertEquals(75, entity.getThreatScore());

        JsonNode rawPayload = jsonMapper.readTree(entity.getRawPayload());
        assertEquals(jsonMapper.valueToTree(event), rawPayload);
        assertEquals("pol-7", rawPayload.get("policyId").asString());
        assertEquals("950001", rawPayload.get("rule").get("ruleId").asString());
    }

    @Test
    void ingest_withoutOptionalProperties_leavesThemNull() {
        SecurityEvent event = event("evt-plain", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityEvent.ActionEnum.MONITOR);

        processingService.ingest(new IngestRequest().event(event));

        verify(securityEventRepository).saveAll(entitiesCaptor.capture());
        SecurityEventEntity entity = entitiesCaptor.getValue().getFirst();
        assertNull(entity.getRule().getRuleId());
        assertNull(entity.getRule().getName());
        assertNull(entity.getRule().getMessage());
        assertNotNull(entity.getRawPayload());
    }

    @Test
    void ingest_batch_persistsAllEventsWithSharedReceivedAt() {
        SecurityEvent first = event("evt-1", "/admin/users",
                Rule.SeverityEnum.HIGH, Rule.CategoryEnum.XSS, SecurityEvent.ActionEnum.ALERT);
        SecurityEvent second = event("evt-2", "/public/index.html",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.INJECTION, SecurityEvent.ActionEnum.MONITOR);

        processingService.ingest(new IngestRequest().events(List.of(first, second)));

        verify(securityEventRepository).saveAll(entitiesCaptor.capture());
        List<SecurityEventEntity> saved = entitiesCaptor.getValue();
        assertEquals(List.of("evt-1", "evt-2"), saved.stream().map(SecurityEventEntity::getEventId).toList());
        assertEquals(saved.get(0).getReceivedAt(), saved.get(1).getReceivedAt());

        // HIGH (30) + ALERT (10) + sensitive path (15)
        assertEquals(55, saved.get(0).getThreatScore());
        assertEquals("Cross-Site Scripting", saved.get(0).getAttackType());
        // LOW (10) + MONITOR (0), no sensitive path
        assertEquals(10, saved.get(1).getThreatScore());
    }

    @Test
    void ingest_unconfiguredCategory_fallsBackToEnumValue() {
        SecurityEvent event = event("evt-bot", "/",
                Rule.SeverityEnum.MEDIUM, Rule.CategoryEnum.BOT, SecurityEvent.ActionEnum.ALERT);

        processingService.ingest(new IngestRequest().event(event));

        verify(securityEventRepository).saveAll(entitiesCaptor.capture());
        assertEquals(Rule.CategoryEnum.BOT.getValue(), entitiesCaptor.getValue().getFirst().getAttackType());
    }

    @Test
    void ingest_threatScore_isCappedAt100() {
        wsaConfig.getSeverities().put("CRITICAL", 90);
        SecurityEvent event = event("evt-cap", "/admin",
                Rule.SeverityEnum.CRITICAL, Rule.CategoryEnum.INJECTION, SecurityEvent.ActionEnum.DENY);

        processingService.ingest(new IngestRequest().event(event));

        verify(securityEventRepository).saveAll(entitiesCaptor.capture());
        assertEquals(100, entitiesCaptor.getValue().getFirst().getThreatScore());
    }

    @Test
    void ingest_bothEventAndEvents_throws() {
        SecurityEvent event = event("evt-1", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityEvent.ActionEnum.MONITOR);
        IngestRequest request = new IngestRequest().event(event).events(List.of(event));

        assertThrows(InvalidIngestRequestException.class, () -> processingService.ingest(request));
        verifyNoInteractions(securityEventRepository);
    }

    @Test
    void ingest_neitherEventNorEvents_throws() {
        assertThrows(InvalidIngestRequestException.class, () -> processingService.ingest(new IngestRequest()));
        verifyNoInteractions(securityEventRepository);
    }

    @Test
    void ingest_emptyEventsList_throws() {
        IngestRequest request = new IngestRequest().events(List.of());

        assertThrows(InvalidIngestRequestException.class, () -> processingService.ingest(request));
        verifyNoInteractions(securityEventRepository);
    }

    @Test
    void ingest_duplicateEventId_propagatesUniqueConstraintViolation() {
        DataIntegrityViolationException conflict = new DataIntegrityViolationException(
                "could not execute statement; constraint [unique_security_events_event_id]");
        when(securityEventRepository.saveAll(anyList())).thenThrow(conflict);
        SecurityEvent event = event("evt-dup", "/",
                Rule.SeverityEnum.HIGH, Rule.CategoryEnum.XSS, SecurityEvent.ActionEnum.DENY);

        DataIntegrityViolationException thrown = assertThrows(DataIntegrityViolationException.class,
                () -> processingService.ingest(new IngestRequest().event(event)));

        // Must reach GlobalExceptionHandler untouched so the constraint name still maps to 409 Conflict
        assertSame(conflict, thrown);
        assertTrue(thrown.getMessage().contains("unique_security_events_event_id"));
    }

    @Test
    void ingest_batchWithConflict_submitsWholeBatchInSingleSave() {
        when(securityEventRepository.saveAll(anyList())).thenThrow(new DataIntegrityViolationException(
                "could not execute statement; constraint [unique_security_events_event_id]"));
        SecurityEvent fresh = event("evt-new", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityEvent.ActionEnum.MONITOR);
        SecurityEvent duplicate = event("evt-dup", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityEvent.ActionEnum.MONITOR);

        assertThrows(DataIntegrityViolationException.class,
                () -> processingService.ingest(new IngestRequest().events(List.of(fresh, duplicate))));

        // One saveAll inside the @Transactional ingest, so the conflict rolls back the whole batch
        verify(securityEventRepository).saveAll(entitiesCaptor.capture());
        assertEquals(List.of("evt-new", "evt-dup"),
                entitiesCaptor.getValue().stream().map(SecurityEventEntity::getEventId).toList());
    }

    @Test
    void ingest_duplicateEventIdsWithinBatch_areSubmittedForDatabaseToReject() {
        SecurityEvent first = event("evt-same", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityEvent.ActionEnum.MONITOR);
        SecurityEvent second = event("evt-same", "/admin",
                Rule.SeverityEnum.HIGH, Rule.CategoryEnum.INJECTION, SecurityEvent.ActionEnum.DENY);

        processingService.ingest(new IngestRequest().events(List.of(first, second)));

        // The service does no de-duplication; the unique constraint is the single source of truth
        verify(securityEventRepository).saveAll(entitiesCaptor.capture());
        assertEquals(2, entitiesCaptor.getValue().size());
    }

    @Test
    void ingest_otherIntegrityViolation_propagates() {
        DataIntegrityViolationException violation = new DataIntegrityViolationException(
                "null value in column \"hostname\" violates not-null constraint");
        when(securityEventRepository.saveAll(anyList())).thenThrow(violation);
        SecurityEvent event = event("evt-null", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityEvent.ActionEnum.MONITOR);
        event.setHostname(null);

        DataIntegrityViolationException thrown = assertThrows(DataIntegrityViolationException.class,
                () -> processingService.ingest(new IngestRequest().event(event)));

        assertSame(violation, thrown);
        assertFalse(thrown.getMessage().contains("unique_security_events_event_id"));
        verify(securityEventRepository).saveAll(entitiesCaptor.capture());
        assertNull(entitiesCaptor.getValue().getFirst().getHostname());
    }

    private static SecurityEvent event(String eventId, String path, Rule.SeverityEnum severity,
                                       Rule.CategoryEnum category, SecurityEvent.ActionEnum action) {
        return new SecurityEvent(eventId, EVENT_TIME, 14227, "pol-7", "203.0.113.42", "www.example.com", path,
                new Rule(severity, category), action);
    }
}
