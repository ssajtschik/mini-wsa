package com.interview.mini_wsa.service;

import com.akamai.wsa.model.IngestRequest;
import com.akamai.wsa.model.StatsSummaryResponse;

import java.time.OffsetDateTime;

public interface ProcessingService {
    void ingest(IngestRequest ingestRequest);

    StatsSummaryResponse getSummary(Long configId, OffsetDateTime from, OffsetDateTime to);
}
