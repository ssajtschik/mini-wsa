package com.interview.mini_wsa.service;

import com.akamai.wsa.model.IngestRequest;

public interface ProcessingService {
    void ingest(IngestRequest ingestRequest);
}
