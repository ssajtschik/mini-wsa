package com.interview.mini_wsa.service;

import com.akamai.wsa.model.*;
import com.interview.mini_wsa.configuration.WsaConfig;
import com.interview.mini_wsa.exception.InvalidIngestRequestException;
import com.interview.mini_wsa.model.SecurityEventEntity;
import com.interview.mini_wsa.repository.ActionStats;
import com.interview.mini_wsa.repository.CategoryStats;
import com.interview.mini_wsa.repository.SecurityEventRepository;
import jakarta.validation.Validator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.json.JsonMapper;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Normalizes an ingest payload into a flat list of events before enrichment.
 *
 * <p>The OpenAPI contract declares {@code event} / {@code events} as a {@code oneOf}, but the
 * generated model exposes both properties and enforces neither, so the exactly-one rule is
 * applied here. Batch items are validated here too, because the generated model only cascades
 * {@code @Valid} into {@code event}, not into the elements of {@code events}.
 */
@Slf4j
@Service
public class ProcessingServiceImpl implements ProcessingService {

    private final WsaConfig wsaConfig;
    private final SecurityEventRepository securityEventRepository;
    private final JsonMapper jsonMapper;
    private final Validator validator;

    public ProcessingServiceImpl(WsaConfig wsaConfig,
                                 SecurityEventRepository securityEventRepository,
                                 JsonMapper jsonMapper,
                                 Validator validator) {
        this.wsaConfig = wsaConfig;
        this.securityEventRepository = securityEventRepository;
        this.jsonMapper = jsonMapper;
        this.validator = validator;
    }

    @Override
    @Transactional
    public void ingest(IngestRequest ingestRequest) {
        List<SecurityEvent> events = extractEvents(ingestRequest);
        validateEvents(events, ingestRequest.getEvent() != null ? "event" : "events");
        log.debug("Processing {} security event(s)", events.size());
        OffsetDateTime now = OffsetDateTime.now();
        List<SecurityEventEntity> entities = events.stream()
                .map(event -> toEntity(event, now))
                .toList();

        securityEventRepository.saveAll(entities);
    }

    @Override
    public StatsSummaryResponse getSummary(Long configId, OffsetDateTime from, OffsetDateTime to) {
        StatsSummaryResponse response = new StatsSummaryResponse();
        response.setConfigId(configId);
        StatsSummaryResponseTimeRange timeRange = new StatsSummaryResponseTimeRange();
        timeRange.setFrom(from);
        timeRange.setTo(to);
        response.setTimeRange(timeRange);
        response.setTotalEvents(securityEventRepository.countByConfigIdAndTimestampBetween(configId, from, to));
        response.setByCategory(securityEventRepository.findCategoryStats(configId, from, to)
                .stream().collect(Collectors.toMap(CategoryStats::getCategory, stat -> new CategoryMetrics(stat.getCount(), stat.getAvgThreatScore()))));
        response.setByAction(securityEventRepository.findActionStats(configId, from, to)
                .stream().collect(Collectors.toMap(ActionStats::getAction, ActionStats::getCount)));
        response.setTopAttackers(securityEventRepository.findTopAttackerStats(configId, from, to)
                .stream().map(attacker -> new AttackerMetric(attacker.getClientIp(), attacker.getCount(), attacker.getAvgThreatScore())).toList());
        response.setTopTargetedPaths(securityEventRepository.findTopPathStats(configId, from, to)
                .stream().map(path -> new PathMetric(path.getPath(), path.getCount())).toList());
        return response;
    }

    private SecurityEventEntity toEntity(SecurityEvent event, OffsetDateTime now) {
        SecurityEventEntity entity = new SecurityEventEntity();
        entity.setEventId(event.getEventId());
        entity.setTimestamp(event.getTimestamp());
        entity.setReceivedAt(now);
        entity.setConfigId(event.getConfigId());
        entity.setPolicyId(event.getPolicyId());
        entity.setClientIp(event.getClientIp());
        entity.setHostname(event.getHostname());
        entity.setPath(event.getPath());
        Rule rule = event.getRule();
        Rule.CategoryEnum category = rule.getCategory();
        entity.setCategory(category.name());
        entity.setSeverity(rule.getSeverity().name());
        entity.setAction(event.getAction().name());
        String attackType = Optional.ofNullable(wsaConfig.getCategories().get(category.name()))
                .orElseGet(() -> {
                    log.warn("Non configured wsa category {}, fallback to provided value {}", category.name(), category.getValue());
                    return category.getValue();
                });
        entity.setAttackType(attackType);
        entity.setThreatScore(evalThreatScore(event));
        entity.setRawPayload(jsonMapper.writeValueAsString(event));
        return entity;
    }

    private int evalThreatScore(SecurityEvent event) {
        int score = 0;
        score += Optional.ofNullable(wsaConfig.getSeverities().get(event.getRule().getSeverity().name())).orElse(0);
        score += Optional.ofNullable(wsaConfig.getActions().get(event.getAction().name())).orElse(0);
        if (containsSensitivePath(event)) {
            score += 15;
        }
//        score += wsaConfig.getRules().stream() / TODO: implement rule check

        return Math.min(score, 100);
    }

    private boolean containsSensitivePath(SecurityEvent event) {
        return wsaConfig.getSensitivePaths().stream()
                .anyMatch(path -> event.getPath().contains(path));
    }

    /**
     * @throws InvalidIngestRequestException listing every violation, prefixed with the event's position
     */
    private void validateEvents(List<SecurityEvent> events, String field) {
        List<String> errors = new ArrayList<>();
        for (int i = 0; i < events.size(); i++) {
            String prefix = "event".equals(field) ? field : field + "[" + i + "]";
            SecurityEvent event = events.get(i);
            if (event == null) {
                errors.add(prefix + ": must not be null");
                continue;
            }
            validator.validate(event).stream()
                    .sorted(Comparator.comparing(v -> v.getPropertyPath().toString()))
                    .map(v -> prefix + "." + v.getPropertyPath() + ": " + v.getMessage())
                    .forEach(errors::add);
        }
        if (!errors.isEmpty()) {
            throw new InvalidIngestRequestException("Invalid security event(s): " + String.join("; ", errors));
        }
    }

    /**
     * @return the events to process, taken from whichever of {@code event} / {@code events} was supplied
     * @throws InvalidIngestRequestException if both were supplied, or neither was
     */
    private List<SecurityEvent> extractEvents(IngestRequest ingestRequest) {
        SecurityEvent single = ingestRequest.getEvent();
        List<SecurityEvent> batch = ingestRequest.getEvents();

        boolean hasSingle = single != null;
        boolean hasBatch = batch != null && !batch.isEmpty();

        if (hasSingle && hasBatch) {
            throw new InvalidIngestRequestException(
                    "Exactly one of 'event' or 'events' must be supplied, but both were present");
        }
        if (!hasSingle && !hasBatch) {
            throw new InvalidIngestRequestException(
                    "Exactly one of 'event' or 'events' must be supplied, but neither was present");
        }

        return hasSingle ? List.of(single) : batch;
    }
}
