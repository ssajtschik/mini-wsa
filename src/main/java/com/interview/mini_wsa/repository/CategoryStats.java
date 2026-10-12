package com.interview.mini_wsa.repository;

/**
 * Per-category aggregate of security events, as returned by
 * {@link SecurityEventRepository#findCategoryStats}.
 */
public interface CategoryStats {
    String getCategory();

    long getCount();

    double getAvgThreatScore();
}
