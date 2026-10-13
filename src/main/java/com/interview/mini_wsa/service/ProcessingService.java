package com.interview.mini_wsa.service;

import com.interview.mini_wsa.model.EnrichedSecurityEvent;
import com.interview.mini_wsa.model.IngestRequest;
import com.interview.mini_wsa.model.StatsSummaryResponse;
import org.springframework.data.domain.Page;

import java.time.OffsetDateTime;

public interface ProcessingService {
    void ingest(IngestRequest ingestRequest);

    StatsSummaryResponse getSummary(Long configId, OffsetDateTime from, OffsetDateTime to);

    Page<EnrichedSecurityEvent> getSecurityEvents(Long configId, OffsetDateTime from, OffsetDateTime to, String category, String action, Integer limit, Integer offset);
}
