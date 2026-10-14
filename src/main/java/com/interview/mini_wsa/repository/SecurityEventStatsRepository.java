package com.interview.mini_wsa.repository;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * Summary aggregates over events with {@code timestamp} between {@code from} and {@code to}
 * (both inclusive). They are restricted to one configuration only if {@code configId} is set,
 * otherwise they cover all configurations.
 */
public interface SecurityEventStatsRepository {

    long countEvents(Long configId, OffsetDateTime from, OffsetDateTime to);

    /** Event count and average threat score per category, most frequent first. */
    List<CategoryStats> findCategoryStats(Long configId, OffsetDateTime from, OffsetDateTime to);

    /** Event count per action, most frequent first. */
    List<ActionStats> findActionStats(Long configId, OffsetDateTime from, OffsetDateTime to);

    /** Event count and average threat score per client IP, top 10. */
    List<AttackerStats> findTopAttackerStats(Long configId, OffsetDateTime from, OffsetDateTime to);

    /** Event count per path, top 10. */
    List<PathStats> findTopPathStats(Long configId, OffsetDateTime from, OffsetDateTime to);
}
