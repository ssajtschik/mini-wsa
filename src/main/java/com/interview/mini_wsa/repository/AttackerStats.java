package com.interview.mini_wsa.repository;

/**
 * Per-attacker aggregate of security events, as returned by
 * {@link SecurityEventStatsRepository#findTopAttackerStats}.
 */
public interface AttackerStats {
    String getClientIp();

    long getCount();

    double getAvgThreatScore();
}
