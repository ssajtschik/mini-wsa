package com.interview.mini_wsa.repository;

import com.interview.mini_wsa.model.SecurityEventEntity;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

public class SecurityEventSpecs {

    public static final String RECEIVED_AT = "receivedAt";
    public static final String CONFIG_ID = "configId";
    public static final String RULE = "rule";
    public static final String CATEGORY = "category";
    public static final String ACTION = "action";

    public static Specification<SecurityEventEntity> filterEvents(
            Long configId,
            String category,
            String action,
            OffsetDateTime from,
            OffsetDateTime to) {

        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (configId != null) {
                predicates.add(cb.equal(root.get(CONFIG_ID), configId));
            }

            if (category != null && !category.isBlank()) {
                predicates.add(cb.equal(root.get(RULE).get(CATEGORY), category));
            }

            if (action != null && !action.isBlank()) {
                predicates.add(cb.equal(root.get(RULE).get(ACTION), action));
            }

            if (from != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get(RECEIVED_AT), from));
            }

            if (to != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get(RECEIVED_AT), to));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    public static Specification<SecurityEventEntity> countMatchingField(
            String fieldName, Object value, long timeWindow) {
        return (root, query, cb) -> {
            Predicate timePredicate = cb.greaterThan(root.get(RECEIVED_AT), OffsetDateTime.now().minusMinutes(timeWindow));
            
            if (value == null) {
                return timePredicate;
            }

            Predicate fieldPredicate = cb.equal(root.get(fieldName), value);
            return cb.and(fieldPredicate, timePredicate);
        };
    }
}