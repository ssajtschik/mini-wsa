package com.interview.mini_wsa.repository;

import com.interview.mini_wsa.model.Rule;
import com.interview.mini_wsa.model.SecurityAction;
import com.interview.mini_wsa.model.SecurityEventEntity;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

public class SecurityEventSpecs {

    public static final String TIMESTAMP = "timestamp";
    public static final String CONFIG_ID = "configId";
    public static final String CATEGORY = "category";
    public static final String ACTION = "action";

    public static Specification<SecurityEventEntity> filterEvents(
            Long configId,
            String category,
            String action,
            OffsetDateTime from,
            OffsetDateTime to) {

        // Parsed eagerly so an unknown value throws IllegalArgumentException here, not wrapped by the repository proxy
        Rule.CategoryEnum categoryFilter = category == null || category.isBlank() ? null : Rule.CategoryEnum.fromValue(category);
        SecurityAction actionFilter = action == null || action.isBlank() ? null : SecurityAction.fromValue(action);

        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (configId != null) {
                predicates.add(cb.equal(root.get(CONFIG_ID), configId));
            }

            if (categoryFilter != null) {
                predicates.add(cb.equal(root.get(CATEGORY), categoryFilter));
            }

            if (actionFilter != null) {
                predicates.add(cb.equal(root.get(ACTION), actionFilter));
            }

            // Same time axis as the summary queries: when the event happened, not when it was ingested
            if (from != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get(TIMESTAMP), from));
            }

            if (to != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get(TIMESTAMP), to));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    public static Specification<SecurityEventEntity> countMatchingField(
            String fieldName, Object value, long timeWindow) {
        return (root, query, cb) -> {
            Predicate timePredicate = cb.greaterThanOrEqualTo(root.get(TIMESTAMP), OffsetDateTime.now().minusMinutes(timeWindow));
            
            if (value == null) {
                return timePredicate;
            }

            Predicate fieldPredicate = cb.equal(root.get(fieldName), value);
            return cb.and(fieldPredicate, timePredicate);
        };
    }
}