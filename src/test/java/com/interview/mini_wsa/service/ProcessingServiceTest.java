package com.interview.mini_wsa.service;

import com.akamai.wsa.model.IngestRequest;
import com.akamai.wsa.model.Rule;
import com.akamai.wsa.model.SecurityEvent;
import com.interview.mini_wsa.configuration.WsaConfig;
import com.interview.mini_wsa.exception.InvalidIngestRequestException;
import com.interview.mini_wsa.model.SecurityEventEntity;
import com.interview.mini_wsa.repository.SecurityEventRepository;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.hibernate.exception.ConstraintViolationException;
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

import java.sql.SQLException;
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
    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

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

        processingService = new ProcessingServiceImpl(wsaConfig, securityEventRepository, jsonMapper, validator);
    }

    @Test
    void ingest_singleEvent_mapsAndPersistsEntity() {
        SecurityEvent event = event("evt-00132", "/api/v1/login",
                Rule.SeverityEnum.CRITICAL, Rule.CategoryEnum.INJECTION, SecurityEvent.ActionEnum.DENY);
        event.getRule()
                .name("SQL Injection Attack")
                .message("SQLi detected in query string");

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
        assertEquals("CRITICAL", entity.getSeverity());
        assertEquals("INJECTION", entity.getCategory());
        assertEquals("SQL/Command Injection", entity.getAttackType());
        // CRITICAL (40) + DENY (20) + sensitive path (15)
        assertEquals(75, entity.getThreatScore());

        JsonNode rawPayload = jsonMapper.readTree(entity.getRawPayload());
        assertEquals("evt-00132", rawPayload.get("eventId").asString());
        assertEquals("2026-05-20T14:32:10Z", rawPayload.get("timestamp").asString());
        assertEquals(14227L, rawPayload.get("configId").asLong());
        assertEquals("pol-7", rawPayload.get("policyId").asString());
        assertEquals("DENY", rawPayload.get("action").asString());
        assertEquals("CRITICAL", rawPayload.get("rule").get("severity").asString());
        assertEquals("950001", rawPayload.get("rule").get("id").asString());
    }

    @Test
    void ingest_withoutOptionalProperties_leavesThemNull() {
        SecurityEvent event = event("evt-plain", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityEvent.ActionEnum.MONITOR);

        processingService.ingest(new IngestRequest().event(event));

        verify(securityEventRepository).saveAll(entitiesCaptor.capture());
        SecurityEventEntity entity = entitiesCaptor.getValue().getFirst();
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
    void ingest_singleEventMissingRequiredField_throwsAndSavesNothing() {
        SecurityEvent event = event("evt-1", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityEvent.ActionEnum.MONITOR);
        event.setPolicyId(null);

        InvalidIngestRequestException thrown = assertThrows(InvalidIngestRequestException.class,
                () -> processingService.ingest(new IngestRequest().event(event)));

        assertTrue(thrown.getMessage().contains("event.policyId: must not be null"), thrown.getMessage());
        verifyNoInteractions(securityEventRepository);
    }

    @Test
    void ingest_batchItemMissingRequiredFields_reportsEveryViolationByIndex() {
        SecurityEvent valid = event("evt-ok", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityEvent.ActionEnum.MONITOR);
        SecurityEvent invalid = event("evt-bad", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityEvent.ActionEnum.MONITOR);
        invalid.setConfigId(null);
        invalid.setHostname(null);
        invalid.getRule().setSeverity(null);

        InvalidIngestRequestException thrown = assertThrows(InvalidIngestRequestException.class,
                () -> processingService.ingest(new IngestRequest().events(List.of(valid, invalid))));

        assertTrue(thrown.getMessage().contains("events[1].configId: must not be null"), thrown.getMessage());
        assertTrue(thrown.getMessage().contains("events[1].hostname: must not be null"), thrown.getMessage());
        assertTrue(thrown.getMessage().contains("events[1].rule.severity: must not be null"), thrown.getMessage());
        assertFalse(thrown.getMessage().contains("events[0]"), thrown.getMessage());
        verifyNoInteractions(securityEventRepository);
    }

    @Test
    void ingest_batchItemMissingRule_throwsInsteadOfNullPointer() {
        SecurityEvent invalid = event("evt-bad", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityEvent.ActionEnum.MONITOR);
        invalid.setRule(null);

        InvalidIngestRequestException thrown = assertThrows(InvalidIngestRequestException.class,
                () -> processingService.ingest(new IngestRequest().events(List.of(invalid))));

        assertTrue(thrown.getMessage().contains("events[0].rule: must not be null"), thrown.getMessage());
        verifyNoInteractions(securityEventRepository);
    }

    @Test
    void ingest_nullBatchItem_throws() {
        SecurityEvent valid = event("evt-ok", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityEvent.ActionEnum.MONITOR);
        List<SecurityEvent> events = new ArrayList<>();
        events.add(valid);
        events.add(null);

        InvalidIngestRequestException thrown = assertThrows(InvalidIngestRequestException.class,
                () -> processingService.ingest(new IngestRequest().events(events)));

        assertTrue(thrown.getMessage().contains("events[1]: must not be null"), thrown.getMessage());
        verifyNoInteractions(securityEventRepository);
    }

    @Test
    void ingest_unconfiguredSeverityAndAction_scoresZero() {
        wsaConfig.getSeverities().remove("LOW");
        wsaConfig.getActions().remove("MONITOR");
        SecurityEvent event = event("evt-zero", "/public",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityEvent.ActionEnum.MONITOR);

        processingService.ingest(new IngestRequest().event(event));

        verify(securityEventRepository).saveAll(entitiesCaptor.capture());
        assertEquals(0, entitiesCaptor.getValue().getFirst().getThreatScore());
    }

    @Test
    void ingest_duplicateEventId_propagatesUniqueConstraintViolation() {
        DataIntegrityViolationException conflict = integrityViolation("unique_security_events_event_id");
        when(securityEventRepository.saveAll(anyList())).thenThrow(conflict);
        SecurityEvent event = event("evt-dup", "/",
                Rule.SeverityEnum.HIGH, Rule.CategoryEnum.XSS, SecurityEvent.ActionEnum.DENY);

        DataIntegrityViolationException thrown = assertThrows(DataIntegrityViolationException.class,
                () -> processingService.ingest(new IngestRequest().event(event)));

        // Must reach GlobalExceptionHandler untouched so the constraint name still maps to 409 Conflict
        assertSame(conflict, thrown);
    }

    @Test
    void ingest_batchWithConflict_submitsWholeBatchInSingleSave() {
        when(securityEventRepository.saveAll(anyList()))
                .thenThrow(integrityViolation("unique_security_events_event_id"));
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
        DataIntegrityViolationException violation = integrityViolation("security_events_threat_score_check");
        when(securityEventRepository.saveAll(anyList())).thenThrow(violation);
        SecurityEvent event = event("evt-check", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityEvent.ActionEnum.MONITOR);

        DataIntegrityViolationException thrown = assertThrows(DataIntegrityViolationException.class,
                () -> processingService.ingest(new IngestRequest().event(event)));

        assertSame(violation, thrown);
    }

    /** Mirrors how Spring wraps a Hibernate constraint violation raised by the repository. */
    private static DataIntegrityViolationException integrityViolation(String constraintName) {
        return new DataIntegrityViolationException("could not execute statement",
                new ConstraintViolationException("constraint violated", new SQLException(), constraintName));
    }

    private static SecurityEvent event(String eventId, String path, Rule.SeverityEnum severity,
                                       Rule.CategoryEnum category, SecurityEvent.ActionEnum action) {
        return new SecurityEvent(eventId, EVENT_TIME, 14227L, "pol-7", "203.0.113.42", "www.example.com", path,
                new Rule("950001", severity, category), action);
    }
}
