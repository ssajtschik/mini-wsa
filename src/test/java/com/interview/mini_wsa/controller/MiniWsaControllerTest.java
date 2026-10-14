package com.interview.mini_wsa.controller;

import com.interview.mini_wsa.exception.GlobalExceptionHandler;
import com.interview.mini_wsa.exception.InvalidIngestRequestException;
import com.interview.mini_wsa.model.*;
import com.interview.mini_wsa.service.ProcessingService;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Web layer only: request binding, status codes and error mapping, with the service mocked. */
@WebMvcTest(MiniWsaController.class)
class MiniWsaControllerTest {

    private static final OffsetDateTime FROM = OffsetDateTime.of(2026, 10, 12, 0, 0, 0, 0, ZoneOffset.UTC);
    private static final OffsetDateTime TO = OffsetDateTime.of(2026, 10, 12, 23, 59, 59, 0, ZoneOffset.UTC);

    private static final String EVENT_JSON = """
            {
              "eventId": "evt-00132",
              "timestamp": "2026-05-20T14:32:10Z",
              "configId": 14227,
              "policyId": "pol-7",
              "clientIp": "203.0.113.42",
              "hostname": "www.example.com",
              "path": "/api/v1/login",
              "rule": {"id": "950001", "severity": "CRITICAL", "category": "INJECTION"},
              "action": "DENY"
            }
            """;

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private ProcessingService processingService;

    // --- ingest ---

    @Test
    void ingest_validEvent_returnsCreatedAndDelegatesToService() throws Exception {
        mockMvc.perform(post("/v1/events/ingest")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"event\": " + EVENT_JSON + "}"))
                .andExpect(status().isCreated());

        ArgumentCaptor<IngestRequest> captor = ArgumentCaptor.forClass(IngestRequest.class);
        verify(processingService).ingest(captor.capture());
        SecurityEvent event = captor.getValue().getEvent();
        assertEquals("evt-00132", event.getEventId());
        assertEquals(SecurityAction.DENY, event.getAction());
        assertEquals(Rule.CategoryEnum.INJECTION, event.getRule().getCategory());
    }

    @Test
    void ingest_malformedJson_returnsBadRequest() throws Exception {
        mockMvc.perform(post("/v1/events/ingest")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"event\": "))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.detail").value("Failed to read request"))
                .andExpect(jsonPath("$.errors").doesNotExist());

        verifyNoInteractions(processingService);
    }

    @Test
    void ingest_unknownEnumValue_returnsBadRequest() throws Exception {
        mockMvc.perform(post("/v1/events/ingest")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"event\": " + EVENT_JSON.replace("\"DENY\"", "\"BLOCK\"") + "}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").value("Failed to read request"));

        verifyNoInteractions(processingService);
    }

    @Test
    void ingest_singleEventMissingRequiredField_returnsBadRequest() throws Exception {
        mockMvc.perform(post("/v1/events/ingest")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"event\": " + EVENT_JSON.replace("\"policyId\": \"pol-7\",", "") + "}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").value("Invalid request content."));

        verifyNoInteractions(processingService);
    }

    @Test
    void ingest_invalidRequest_returnsMessageAndViolations() throws Exception {
        doThrow(new InvalidIngestRequestException("Invalid security event(s).",
                List.of("events[0].hostname: must not be null")))
                .when(processingService).ingest(any());

        mockMvc.perform(post("/v1/events/ingest")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"events\": []}"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.detail").value("Invalid security event(s)."))
                .andExpect(jsonPath("$.errors[0]").value("events[0].hostname: must not be null"));
    }

    @Test
    void ingest_duplicateEventId_returnsConflict() throws Exception {
        doThrow(new DataIntegrityViolationException("duplicate", new ConstraintViolationException(
                "duplicate", new SQLException(), "unique_security_events_event_id")))
                .when(processingService).ingest(any());

        mockMvc.perform(post("/v1/events/ingest")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"event\": " + EVENT_JSON + "}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.detail").value(GlobalExceptionHandler.DUPLICATE_EVENT));
    }

    // --- samples ---

    @Test
    void getSamples_bindsAllQueryParameters() throws Exception {
        when(processingService.getSecurityEvents(any(), any(), any(), any(), any(), anyInt(), anyInt()))
                .thenReturn(new PageImpl<>(List.of(), PageRequest.of(2, 10), 0));

        mockMvc.perform(get("/v1/events/samples")
                        .param("configId", "14227")
                        .param("from", "2026-10-12T00:00:00Z")
                        .param("to", "2026-10-12T23:59:59Z")
                        .param("category", "INJECTION")
                        .param("action", "DENY")
                        .param("limit", "10")
                        .param("offset", "20"))
                .andExpect(status().isOk());

        verify(processingService).getSecurityEvents(14227L, FROM, TO, "INJECTION", "DENY", 10, 20);
    }

    @Test
    void getSamples_withoutParameters_usesContractDefaults() throws Exception {
        when(processingService.getSecurityEvents(any(), any(), any(), any(), any(), anyInt(), anyInt()))
                .thenReturn(new PageImpl<>(List.of(), PageRequest.of(0, 20), 0));

        mockMvc.perform(get("/v1/events/samples"))
                .andExpect(status().isOk());

        verify(processingService).getSecurityEvents(isNull(), isNull(), isNull(), isNull(), isNull(), eq(20), eq(0));
    }

    @Test
    void getSamples_returnsPageOfEnrichedEvents() throws Exception {
        EnrichedSecurityEvent event = new EnrichedSecurityEvent();
        event.setEventId("evt-00132");
        event.setThreatScore(75);
        event.setAction(SecurityAction.DENY);
        when(processingService.getSecurityEvents(any(), any(), any(), any(), any(), anyInt(), anyInt()))
                .thenReturn(new PageImpl<>(List.of(event), PageRequest.of(0, 20), 1));

        mockMvc.perform(get("/v1/events/samples").param("configId", "14227"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.content[0].eventId").value("evt-00132"))
                .andExpect(jsonPath("$.content[0].threatScore").value(75))
                .andExpect(jsonPath("$.content[0].action").value("DENY"));
    }

    @Test
    void getSamples_invalidPagination_returnsBadRequest() throws Exception {
        when(processingService.getSecurityEvents(any(), any(), any(), any(), any(), anyInt(), anyInt()))
                .thenThrow(new IllegalArgumentException("Offset cannot be negative."));

        mockMvc.perform(get("/v1/events/samples").param("offset", "-1"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").value("Offset cannot be negative."))
                .andExpect(jsonPath("$.errors").doesNotExist());
    }

    @Test
    void getSamples_limitAboveMaximum_returnsBadRequest() throws Exception {
        mockMvc.perform(get("/v1/events/samples").param("limit", "101"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").value(GlobalExceptionHandler.VALIDATION_FAILED))
                .andExpect(jsonPath("$.errors[0]").value("limit: must be less than or equal to 100"));

        verifyNoInteractions(processingService);
    }

    @Test
    void getSamples_unparsableDate_returnsBadRequest() throws Exception {
        mockMvc.perform(get("/v1/events/samples").param("from", "yesterday"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").value("Failed to convert 'from' with value: 'yesterday'"));

        verifyNoInteractions(processingService);
    }

    // --- summary ---

    @Test
    void getSummary_returnsServiceResponseAsJson() throws Exception {
        StatsSummaryResponse response = new StatsSummaryResponse(
                new StatsSummaryResponseTimeRange(FROM, TO),
                1523L,
                Map.of("INJECTION", new CategoryMetrics(450L, 72.3)),
                Map.of("DENY", 890L),
                List.of(new AttackerMetric("203.0.113.42", 87L, 81.2)),
                List.of(new PathMetric("/api/v1/login", 234L)))
                .configId(14227L);
        when(processingService.getSummary(14227L, FROM, TO)).thenReturn(response);

        mockMvc.perform(get("/v1/stats/summary")
                        .param("configId", "14227")
                        .param("from", "2026-10-12T00:00:00Z")
                        .param("to", "2026-10-12T23:59:59Z"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.configId").value(14227))
                .andExpect(jsonPath("$.totalEvents").value(1523))
                .andExpect(jsonPath("$.byCategory.INJECTION.count").value(450))
                .andExpect(jsonPath("$.byCategory.INJECTION.avgThreatScore").value(72.3))
                .andExpect(jsonPath("$.byAction.DENY").value(890))
                .andExpect(jsonPath("$.topAttackers[0].clientIp").value("203.0.113.42"))
                .andExpect(jsonPath("$.topTargetedPaths[0].path").value("/api/v1/login"));
    }

    @Test
    void getSummary_withoutConfigId_passesNullToService() throws Exception {
        when(processingService.getSummary(null, FROM, TO)).thenReturn(
                new StatsSummaryResponse(new StatsSummaryResponseTimeRange(FROM, TO), 42L,
                        Map.of(), Map.of(), List.of(), List.of()));

        mockMvc.perform(get("/v1/stats/summary")
                        .param("from", "2026-10-12T00:00:00Z")
                        .param("to", "2026-10-12T23:59:59Z"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalEvents").value(42));
    }

    @Test
    void getSummary_unparsableConfigId_returnsBadRequest() throws Exception {
        mockMvc.perform(get("/v1/stats/summary")
                        .param("configId", "abc")
                        .param("from", "2026-10-12T00:00:00Z")
                        .param("to", "2026-10-12T23:59:59Z"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").value("Failed to convert 'configId' with value: 'abc'"));

        verifyNoInteractions(processingService);
    }
}
