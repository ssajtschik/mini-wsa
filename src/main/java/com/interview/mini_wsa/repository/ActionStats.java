package com.interview.mini_wsa.repository;

/**
 * Per-action aggregate of security events, as returned by
 * {@link SecurityEventStatsRepository#findActionStats}.
 */
public interface ActionStats {
    String getAction();

    long getCount();
}
