package com.interview.mini_wsa.repository;

/**
 * Per-path aggregate of security events, as returned by
 * {@link SecurityEventStatsRepository#findTopPathStats}.
 */
public interface PathStats {
    String getPath();

    long getCount();
}
