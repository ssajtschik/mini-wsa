package com.interview.mini_wsa.repository;

import com.interview.mini_wsa.model.SecurityEventEntity;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Tuple;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Root;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * Builds the summary queries with the Criteria API so the {@code configId} predicate is only
 * added when a configId is given (see {@link SecurityEventSpecs#filterEvents}).
 */
class SecurityEventStatsRepositoryImpl implements SecurityEventStatsRepository {

    private static final int TOP_LIMIT = 10;

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public long countEvents(Long configId, OffsetDateTime from, OffsetDateTime to) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<Long> query = cb.createQuery(Long.class);
        Root<SecurityEventEntity> root = query.from(SecurityEventEntity.class);
        query.select(cb.count(root))
                .where(SecurityEventSpecs.filterEvents(configId, null, null, from, to).toPredicate(root, query, cb));
        return entityManager.createQuery(query).getSingleResult();
    }

    @Override
    public List<CategoryStats> findCategoryStats(Long configId, OffsetDateTime from, OffsetDateTime to) {
        return List.copyOf(groupBy(SecurityEventSpecs.CATEGORY, configId, from, to, null));
    }

    @Override
    public List<ActionStats> findActionStats(Long configId, OffsetDateTime from, OffsetDateTime to) {
        return List.copyOf(groupBy(SecurityEventSpecs.ACTION, configId, from, to, null));
    }

    @Override
    public List<AttackerStats> findTopAttackerStats(Long configId, OffsetDateTime from, OffsetDateTime to) {
        return List.copyOf(groupBy("clientIp", configId, from, to, TOP_LIMIT));
    }

    @Override
    public List<PathStats> findTopPathStats(Long configId, OffsetDateTime from, OffsetDateTime to) {
        return List.copyOf(groupBy("path", configId, from, to, TOP_LIMIT));
    }

    /** Count and average threat score per value of {@code field}, most frequent first. */
    private List<Group> groupBy(String field, Long configId, OffsetDateTime from, OffsetDateTime to, Integer limit) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<Tuple> query = cb.createTupleQuery();
        Root<SecurityEventEntity> root = query.from(SecurityEventEntity.class);
        Expression<Object> key = root.get(field);
        Expression<Long> count = cb.count(root);
        query.multiselect(key, count, cb.avg(root.get("threatScore")))
                .where(SecurityEventSpecs.filterEvents(configId, null, null, from, to).toPredicate(root, query, cb))
                .groupBy(key)
                .orderBy(cb.desc(count));

        var typedQuery = entityManager.createQuery(query);
        if (limit != null) {
            typedQuery.setMaxResults(limit);
        }
        return typedQuery.getResultList().stream()
                .map(t -> new Group(String.valueOf(t.get(0)), t.get(1, Long.class), t.get(2, Double.class)))
                .toList();
    }

    /** One grouped row; the grouped value is exposed under the name each projection expects. */
    private record Group(String key, long count, double avgThreatScore)
            implements CategoryStats, ActionStats, AttackerStats, PathStats {

        @Override
        public String getCategory() {
            return key;
        }

        @Override
        public String getAction() {
            return key;
        }

        @Override
        public String getClientIp() {
            return key;
        }

        @Override
        public String getPath() {
            return key;
        }

        @Override
        public long getCount() {
            return count;
        }

        @Override
        public double getAvgThreatScore() {
            return avgThreatScore;
        }
    }
}
