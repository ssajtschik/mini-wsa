package com.interview.mini_wsa.controller;

import com.interview.mini_wsa.api.V1Api;
import com.interview.mini_wsa.model.EnrichedSecurityEvent;
import com.interview.mini_wsa.model.IngestRequest;
import com.interview.mini_wsa.model.StatsSummaryResponse;
import com.interview.mini_wsa.service.ProcessingService;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

import java.time.OffsetDateTime;

import static org.springframework.http.ResponseEntity.ok;
import static org.springframework.http.ResponseEntity.status;

@RestController
public class MiniWsaController implements V1Api {

    private final ProcessingService processingService;

    public MiniWsaController(ProcessingService processingService) {
        this.processingService = processingService;
    }

    @Override
    public ResponseEntity<Void> ingestEvents(IngestRequest ingestRequest) {
        processingService.ingest(ingestRequest);
        return status(HttpStatus.CREATED).build();
    }

    @Override
    public ResponseEntity<Page<EnrichedSecurityEvent>> getSamples(Long configId, OffsetDateTime from, OffsetDateTime to, String category, String action, Integer limit, Integer offset) {
        Page<EnrichedSecurityEvent> securityEvents = processingService.getSecurityEvents(configId, from, to, category, action, limit, offset);
        return ok(securityEvents);
    }

    @Override
    public ResponseEntity<StatsSummaryResponse> getSummary(Long configId, OffsetDateTime from, OffsetDateTime to) {
        StatsSummaryResponse response = processingService.getSummary(configId, from, to);
        return ok(response);
    }
}
