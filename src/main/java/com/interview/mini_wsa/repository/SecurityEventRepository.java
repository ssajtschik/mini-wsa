package com.interview.mini_wsa.repository;

import com.interview.mini_wsa.model.SecurityEventEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.List;

@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEventEntity, Long>, JpaSpecificationExecutor<SecurityEventEntity> {
    long countByConfigIdAndTimestampBetween(Long configId, OffsetDateTime from, OffsetDateTime to);

    /**
     * Event count and average threat score per category for one configuration, with
     * {@code timestamp} between {@code from} and {@code to} (both inclusive).
     */
    @Query("""
            SELECT e.category AS category,
                   COUNT(e) AS count,
                   AVG(e.threatScore) AS avgThreatScore
            FROM SecurityEventEntity e
            WHERE e.configId = :configId
              AND e.timestamp BETWEEN :from AND :to
            GROUP BY e.category
            ORDER BY COUNT(e) DESC
            """)
    List<CategoryStats> findCategoryStats(@Param("configId") Long configId,
                                          @Param("from") OffsetDateTime from,
                                          @Param("to") OffsetDateTime to);

    /**
     * Event count and average threat score per action for one configuration, with
     * {@code timestamp} between {@code from} and {@code to} (both inclusive).
     */
    @Query("""
            SELECT e.action AS action,
                   COUNT(e) AS count
            FROM SecurityEventEntity e
            WHERE e.configId = :configId
              AND e.timestamp BETWEEN :from AND :to
            GROUP BY e.action
            ORDER BY COUNT(e) DESC
            """)
    List<ActionStats> findActionStats(@Param("configId") Long configId,
                                      @Param("from") OffsetDateTime from,
                                      @Param("to") OffsetDateTime to);

    /**
     * Event count and average threat score per client-ip for one configuration, with
     * {@code timestamp} between {@code from} and {@code to} (both inclusive), limit to 10.
     */
    @Query("""
            SELECT e.clientIp AS clientIp,
                   COUNT(e) AS count,
                   AVG(e.threatScore) AS avgThreatScore
            FROM SecurityEventEntity e
            WHERE e.configId = :configId
              AND e.timestamp BETWEEN :from AND :to
            GROUP BY e.clientIp
            ORDER BY COUNT(e) DESC
            LIMIT 10
            """)
    List<AttackerStats> findTopAttackerStats(@Param("configId") Long configId,
                                             @Param("from") OffsetDateTime from,
                                             @Param("to") OffsetDateTime to);

    /**
     * Event count and average threat score per path for one configuration, with
     * {@code timestamp} between {@code from} and {@code to} (both inclusive), limit to 10.
     */
    @Query("""
            SELECT e.path AS path,
                   COUNT(e) AS count
            FROM SecurityEventEntity e
            WHERE e.configId = :configId
              AND e.timestamp BETWEEN :from AND :to
            GROUP BY e.path
            ORDER BY COUNT(e) DESC
            LIMIT 10
            """)
    List<PathStats> findTopPathStats(@Param("configId") Long configId,
                                     @Param("from") OffsetDateTime from,
                                     @Param("to") OffsetDateTime to);
}
