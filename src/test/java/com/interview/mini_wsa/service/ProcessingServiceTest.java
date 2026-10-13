package com.interview.mini_wsa.service;

import com.interview.mini_wsa.model.*;
import com.interview.mini_wsa.configuration.WsaConfig;
import com.interview.mini_wsa.exception.InvalidIngestRequestException;
import com.interview.mini_wsa.repository.ActionStats;
import com.interview.mini_wsa.repository.AttackerStats;
import com.interview.mini_wsa.repository.CategoryStats;
import com.interview.mini_wsa.repository.PathStats;
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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class ProcessingServiceTest {

    private static final OffsetDateTime EVENT_TIME = OffsetDateTime.of(2026, 5, 20, 14, 32, 10, 0, ZoneOffset.UTC);
    private static final OffsetDateTime FROM = OffsetDateTime.of(2026, 10, 12, 0, 0, 0, 0, ZoneOffset.UTC);
    private static final OffsetDateTime TO = OffsetDateTime.of(2026, 10, 12, 23, 59, 59, 0, ZoneOffset.UTC);

    @Mock
    private SecurityEventRepository securityEventRepository;

    @Captor
    private ArgumentCaptor<List<SecurityEventEntity>> entitiesCaptor;

    @Captor
    private ArgumentCaptor<Pageable> pageableCaptor;

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
                Rule.SeverityEnum.CRITICAL, Rule.CategoryEnum.INJECTION, SecurityAction.DENY);
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
        assertEquals(SecurityAction.DENY, entity.getAction());
        assertEquals(Rule.SeverityEnum.CRITICAL, entity.getSeverity());
        assertEquals(Rule.CategoryEnum.INJECTION, entity.getCategory());
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
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityAction.MONITOR);

        processingService.ingest(new IngestRequest().event(event));

        verify(securityEventRepository).saveAll(entitiesCaptor.capture());
        SecurityEventEntity entity = entitiesCaptor.getValue().getFirst();
        assertNotNull(entity.getRawPayload());
    }

    @Test
    void ingest_batch_persistsAllEventsWithSharedReceivedAt() {
        SecurityEvent first = event("evt-1", "/admin/users",
                Rule.SeverityEnum.HIGH, Rule.CategoryEnum.XSS, SecurityAction.ALERT);
        SecurityEvent second = event("evt-2", "/public/index.html",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.INJECTION, SecurityAction.MONITOR);

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
                Rule.SeverityEnum.MEDIUM, Rule.CategoryEnum.BOT, SecurityAction.ALERT);

        processingService.ingest(new IngestRequest().event(event));

        verify(securityEventRepository).saveAll(entitiesCaptor.capture());
        assertEquals(Rule.CategoryEnum.BOT.getValue(), entitiesCaptor.getValue().getFirst().getAttackType());
    }

    @Test
    void ingest_threatScore_isCappedAt100() {
        wsaConfig.getSeverities().put("CRITICAL", 90);
        SecurityEvent event = event("evt-cap", "/admin",
                Rule.SeverityEnum.CRITICAL, Rule.CategoryEnum.INJECTION, SecurityAction.DENY);

        processingService.ingest(new IngestRequest().event(event));

        verify(securityEventRepository).saveAll(entitiesCaptor.capture());
        assertEquals(100, entitiesCaptor.getValue().getFirst().getThreatScore());
    }

    @Test
    void ingest_bothEventAndEvents_throws() {
        SecurityEvent event = event("evt-1", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityAction.MONITOR);
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
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityAction.MONITOR);
        event.setPolicyId(null);

        InvalidIngestRequestException thrown = assertThrows(InvalidIngestRequestException.class,
                () -> processingService.ingest(new IngestRequest().event(event)));

        assertTrue(thrown.getMessage().contains("event.policyId: must not be null"), thrown.getMessage());
        verifyNoInteractions(securityEventRepository);
    }

    @Test
    void ingest_batchItemMissingRequiredFields_reportsEveryViolationByIndex() {
        SecurityEvent valid = event("evt-ok", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityAction.MONITOR);
        SecurityEvent invalid = event("evt-bad", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityAction.MONITOR);
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
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityAction.MONITOR);
        invalid.setRule(null);

        InvalidIngestRequestException thrown = assertThrows(InvalidIngestRequestException.class,
                () -> processingService.ingest(new IngestRequest().events(List.of(invalid))));

        assertTrue(thrown.getMessage().contains("events[0].rule: must not be null"), thrown.getMessage());
        verifyNoInteractions(securityEventRepository);
    }

    @Test
    void ingest_nullBatchItem_throws() {
        SecurityEvent valid = event("evt-ok", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityAction.MONITOR);
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
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityAction.MONITOR);

        processingService.ingest(new IngestRequest().event(event));

        verify(securityEventRepository).saveAll(entitiesCaptor.capture());
        assertEquals(0, entitiesCaptor.getValue().getFirst().getThreatScore());
    }

    @Test
    void ingest_duplicateEventId_propagatesUniqueConstraintViolation() {
        DataIntegrityViolationException conflict = integrityViolation("unique_security_events_event_id");
        when(securityEventRepository.saveAll(anyList())).thenThrow(conflict);
        SecurityEvent event = event("evt-dup", "/",
                Rule.SeverityEnum.HIGH, Rule.CategoryEnum.XSS, SecurityAction.DENY);

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
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityAction.MONITOR);
        SecurityEvent duplicate = event("evt-dup", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityAction.MONITOR);

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
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityAction.MONITOR);
        SecurityEvent second = event("evt-same", "/admin",
                Rule.SeverityEnum.HIGH, Rule.CategoryEnum.INJECTION, SecurityAction.DENY);

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
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityAction.MONITOR);

        DataIntegrityViolationException thrown = assertThrows(DataIntegrityViolationException.class,
                () -> processingService.ingest(new IngestRequest().event(event)));

        assertSame(violation, thrown);
    }

    // --- threat score: windowed rules ---

    @Test
    void ingest_ruleThresholdReached_addsRuleScore() {
        wsaConfig.setRules(List.of(rule(5, 10, "clientIp", 15)));
        when(securityEventRepository.count(any(Specification.class))).thenReturn(5L);
        SecurityEvent event = event("evt-rule", "/public",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityAction.MONITOR);

        processingService.ingest(new IngestRequest().event(event));

        verify(securityEventRepository).saveAll(entitiesCaptor.capture());
        // LOW (10) + MONITOR (0) + rule (15)
        assertEquals(25, entitiesCaptor.getValue().getFirst().getThreatScore());
    }

    @Test
    void ingest_ruleThresholdNotReached_addsNothing() {
        wsaConfig.setRules(List.of(rule(5, 10, "clientIp", 15)));
        when(securityEventRepository.count(any(Specification.class))).thenReturn(4L);
        SecurityEvent event = event("evt-rule", "/public",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityAction.MONITOR);

        processingService.ingest(new IngestRequest().event(event));

        verify(securityEventRepository).saveAll(entitiesCaptor.capture());
        assertEquals(10, entitiesCaptor.getValue().getFirst().getThreatScore());
    }

    @Test
    void ingest_multipleRules_sumOnlyMatchingOnesAndAreCappedAt100() {
        wsaConfig.setRules(List.of(
                rule(5, 10, "clientIp", 30),
                rule(3, 5, "path", 40),
                rule(100, 60, "hostname", 50)));
        when(securityEventRepository.count(any(Specification.class))).thenReturn(5L, 3L, 99L);
        SecurityEvent event = event("evt-rules", "/admin",
                Rule.SeverityEnum.HIGH, Rule.CategoryEnum.INJECTION, SecurityAction.DENY);

        processingService.ingest(new IngestRequest().event(event));

        verify(securityEventRepository, times(3)).count(any(Specification.class));
        verify(securityEventRepository).saveAll(entitiesCaptor.capture());
        // HIGH (30) + DENY (20) + sensitive path (15) + clientIp rule (30) + path rule (40) = 135, capped
        assertEquals(100, entitiesCaptor.getValue().getFirst().getThreatScore());
    }

    @Test
    void ingest_rulesAreEvaluatedPerEventInBatch() {
        wsaConfig.setRules(List.of(rule(2, 10, "clientIp", 15)));
        when(securityEventRepository.count(any(Specification.class))).thenReturn(2L, 0L);
        SecurityEvent first = event("evt-1", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityAction.MONITOR);
        SecurityEvent second = event("evt-2", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityAction.MONITOR);

        processingService.ingest(new IngestRequest().events(List.of(first, second)));

        verify(securityEventRepository).saveAll(entitiesCaptor.capture());
        assertEquals(List.of(25, 10),
                entitiesCaptor.getValue().stream().map(SecurityEventEntity::getThreatScore).toList());
    }

    @Test
    void ingest_ruleWithUnknownMatchingField_throwsAndSavesNothing() {
        wsaConfig.setRules(List.of(rule(1, 10, "doesNotExist", 15)));
        SecurityEvent event = event("evt-rule", "/",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityAction.MONITOR);

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> processingService.ingest(new IngestRequest().event(event)));

        assertEquals("Unknown field: doesNotExist", thrown.getMessage());
        verify(securityEventRepository, never()).saveAll(anyList());
    }

    @Test
    void getValue_readsEventPropertyByName() {
        SecurityEvent event = event("evt-1", "/login",
                Rule.SeverityEnum.LOW, Rule.CategoryEnum.XSS, SecurityAction.MONITOR);

        assertEquals("203.0.113.42", ProcessingServiceImpl.getValue(event, "clientIp"));
        assertEquals("/login", ProcessingServiceImpl.getValue(event, "path"));
        assertEquals(14227L, ProcessingServiceImpl.getValue(event, "configId"));
    }

    // --- getSummary ---

    @Test
    void getSummary_mapsRepositoryAggregatesIntoResponse() {
        when(securityEventRepository.countByConfigIdAndTimestampBetween(14227L, FROM, TO)).thenReturn(1523L);
        when(securityEventRepository.findCategoryStats(14227L, FROM, TO)).thenReturn(List.of(
                categoryStats("INJECTION", 450, 72.3),
                categoryStats("BOT", 380, 45.1)));
        when(securityEventRepository.findActionStats(14227L, FROM, TO)).thenReturn(List.of(
                actionStats("DENY", 890),
                actionStats("ALERT", 433),
                actionStats("MONITOR", 200)));
        when(securityEventRepository.findTopAttackerStats(14227L, FROM, TO)).thenReturn(List.of(
                attackerStats("203.0.113.42", 87, 81.2),
                attackerStats("198.51.100.7", 12, 40.0)));
        when(securityEventRepository.findTopPathStats(14227L, FROM, TO)).thenReturn(List.of(
                pathStats("/api/v1/login", 234),
                pathStats("/admin", 101)));

        StatsSummaryResponse response = processingService.getSummary(14227L, FROM, TO);

        assertEquals(14227L, response.getConfigId());
        assertEquals(FROM, response.getTimeRange().getFrom());
        assertEquals(TO, response.getTimeRange().getTo());
        assertEquals(1523L, response.getTotalEvents());
        assertEquals(Map.of(
                        "INJECTION", new CategoryMetrics(450L, 72.3),
                        "BOT", new CategoryMetrics(380L, 45.1)),
                response.getByCategory());
        assertEquals(Map.of("DENY", 890L, "ALERT", 433L, "MONITOR", 200L), response.getByAction());
        // Repository ordering (most frequent first) must be preserved
        assertEquals(List.of(
                        new AttackerMetric("203.0.113.42", 87L, 81.2),
                        new AttackerMetric("198.51.100.7", 12L, 40.0)),
                response.getTopAttackers());
        assertEquals(List.of(
                        new PathMetric("/api/v1/login", 234L),
                        new PathMetric("/admin", 101L)),
                response.getTopTargetedPaths());
    }

    @Test
    void getSummary_noEvents_returnsZeroTotalAndEmptyCollections() {
        when(securityEventRepository.countByConfigIdAndTimestampBetween(14227L, FROM, TO)).thenReturn(0L);
        when(securityEventRepository.findCategoryStats(14227L, FROM, TO)).thenReturn(List.of());
        when(securityEventRepository.findActionStats(14227L, FROM, TO)).thenReturn(List.of());
        when(securityEventRepository.findTopAttackerStats(14227L, FROM, TO)).thenReturn(List.of());
        when(securityEventRepository.findTopPathStats(14227L, FROM, TO)).thenReturn(List.of());

        StatsSummaryResponse response = processingService.getSummary(14227L, FROM, TO);

        assertEquals(14227L, response.getConfigId());
        assertEquals(0L, response.getTotalEvents());
        assertTrue(response.getByCategory().isEmpty());
        assertTrue(response.getByAction().isEmpty());
        assertTrue(response.getTopAttackers().isEmpty());
        assertTrue(response.getTopTargetedPaths().isEmpty());
    }

    // --- getSecurityEvents ---

    @Test
    void getSecurityEvents_mapsEntitiesToEnrichedEvents() {
        when(securityEventRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(entity("evt-00132")), PageRequest.of(0, 20), 1));

        Page<EnrichedSecurityEvent> page = processingService.getSecurityEvents(
                14227L, FROM, TO, "INJECTION", "DENY", 20, 0);

        assertEquals(1, page.getTotalElements());
        EnrichedSecurityEvent event = page.getContent().getFirst();
        assertEquals("evt-00132", event.getEventId());
        assertEquals(EVENT_TIME, event.getTimestamp());
        assertEquals(14227L, event.getConfigId());
        assertEquals("pol-7", event.getPolicyId());
        assertEquals("203.0.113.42", event.getClientIp());
        assertEquals("www.example.com", event.getHostname());
        assertEquals("/api/v1/login", event.getPath());
        assertEquals(SecurityAction.DENY, event.getAction());
        assertEquals(EVENT_TIME.plusSeconds(1), event.getReceivedAt());
        assertEquals(75, event.getThreatScore());
        assertEquals(Rule.SeverityEnum.CRITICAL, event.getRule().getSeverity());
        assertEquals(Rule.CategoryEnum.INJECTION, event.getRule().getCategory());
    }

    @Test
    void getSecurityEvents_translatesLimitAndOffsetIntoPageRequestSortedByTimestampDesc() {
        when(securityEventRepository.findAll(any(Specification.class), pageableCaptor.capture()))
                .thenReturn(Page.empty());

        processingService.getSecurityEvents(14227L, FROM, TO, null, null, 20, 40);

        Pageable pageable = pageableCaptor.getValue();
        assertEquals(2, pageable.getPageNumber());
        assertEquals(20, pageable.getPageSize());
        assertEquals(40, pageable.getOffset());
        assertEquals(Sort.by("timestamp").descending(), pageable.getSort());
    }

    @Test
    void getSecurityEvents_preservesPagingMetadata() {
        PageRequest pageRequest = PageRequest.of(1, 2, ProcessingServiceImpl.DEFAULT_SORT);
        when(securityEventRepository.findAll(any(Specification.class), eq(pageRequest)))
                .thenReturn(new PageImpl<>(List.of(entity("evt-3"), entity("evt-4")), pageRequest, 5));

        Page<EnrichedSecurityEvent> page = processingService.getSecurityEvents(
                null, null, null, null, null, 2, 2);

        assertEquals(List.of("evt-3", "evt-4"),
                page.getContent().stream().map(EnrichedSecurityEvent::getEventId).toList());
        assertEquals(5, page.getTotalElements());
        assertEquals(3, page.getTotalPages());
        assertEquals(1, page.getNumber());
        assertEquals(2, page.getSize());
    }

    @Test
    void getSecurityEvents_noMatches_returnsEmptyPage() {
        when(securityEventRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(Page.empty(PageRequest.of(0, 20)));

        Page<EnrichedSecurityEvent> page = processingService.getSecurityEvents(
                14227L, FROM, TO, "XSS", "ALERT", 20, 0);

        assertTrue(page.isEmpty());
        assertEquals(0, page.getTotalElements());
    }

    @Test
    void getSecurityEvents_nonPositiveLimit_throws() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> processingService.getSecurityEvents(14227L, FROM, TO, null, null, 0, 0));

        assertEquals("Limit must be greater than 0.", thrown.getMessage());
        verifyNoInteractions(securityEventRepository);
    }

    @Test
    void getSecurityEvents_negativeOffset_throws() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> processingService.getSecurityEvents(14227L, FROM, TO, null, null, 20, -20));

        assertEquals("Offset cannot be negative.", thrown.getMessage());
        verifyNoInteractions(securityEventRepository);
    }

    @Test
    void getSecurityEvents_offsetNotMultipleOfLimit_throws() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> processingService.getSecurityEvents(14227L, FROM, TO, null, null, 20, 15));

        assertTrue(thrown.getMessage().contains("Invalid offset (15)"), thrown.getMessage());
        assertTrue(thrown.getMessage().contains("Expected values include: 0, 20, 40, 60"), thrown.getMessage());
        verifyNoInteractions(securityEventRepository);
    }

    private static WsaConfig.WsaRule rule(int count, int windowMinutes, String matchingField, int score) {
        WsaConfig.WsaRule rule = new WsaConfig.WsaRule();
        rule.setCount(count);
        rule.setWindowMinutes(windowMinutes);
        rule.setMatchingField(matchingField);
        rule.setScore(score);
        return rule;
    }

    private static SecurityEventEntity entity(String eventId) {
        SecurityEventEntity entity = new SecurityEventEntity();
        entity.setEventId(eventId);
        entity.setTimestamp(EVENT_TIME);
        entity.setReceivedAt(EVENT_TIME.plusSeconds(1));
        entity.setConfigId(14227L);
        entity.setPolicyId("pol-7");
        entity.setClientIp("203.0.113.42");
        entity.setHostname("www.example.com");
        entity.setPath("/api/v1/login");
        entity.setAction(SecurityAction.DENY);
        entity.setSeverity(Rule.SeverityEnum.CRITICAL);
        entity.setCategory(Rule.CategoryEnum.INJECTION);
        entity.setAttackType("SQL/Command Injection");
        entity.setThreatScore(75);
        return entity;
    }

    private static CategoryStats categoryStats(String category, long count, double avgThreatScore) {
        return new CategoryStats() {
            public String getCategory() { return category; }
            public long getCount() { return count; }
            public double getAvgThreatScore() { return avgThreatScore; }
        };
    }

    private static ActionStats actionStats(String action, long count) {
        return new ActionStats() {
            public String getAction() { return action; }
            public long getCount() { return count; }
        };
    }

    private static AttackerStats attackerStats(String clientIp, long count, double avgThreatScore) {
        return new AttackerStats() {
            public String getClientIp() { return clientIp; }
            public long getCount() { return count; }
            public double getAvgThreatScore() { return avgThreatScore; }
        };
    }

    private static PathStats pathStats(String path, long count) {
        return new PathStats() {
            public String getPath() { return path; }
            public long getCount() { return count; }
        };
    }

    /** Mirrors how Spring wraps a Hibernate constraint violation raised by the repository. */
    private static DataIntegrityViolationException integrityViolation(String constraintName) {
        return new DataIntegrityViolationException("could not execute statement",
                new ConstraintViolationException("constraint violated", new SQLException(), constraintName));
    }

    private static SecurityEvent event(String eventId, String path, Rule.SeverityEnum severity,
                                       Rule.CategoryEnum category, SecurityAction action) {
        return new SecurityEvent(eventId, EVENT_TIME, 14227L, "pol-7", "203.0.113.42", "www.example.com", path,
                new Rule("950001", severity, category), action);
    }
}
