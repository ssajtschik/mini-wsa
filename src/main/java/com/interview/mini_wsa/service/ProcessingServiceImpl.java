package com.interview.mini_wsa.service;

import com.akamai.wsa.model.IngestRequest;
import com.akamai.wsa.model.Rule;
import com.akamai.wsa.model.SecurityEvent;
import com.interview.mini_wsa.configuration.WsaConfig;
import com.interview.mini_wsa.exception.InvalidIngestRequestException;
import com.interview.mini_wsa.model.RuleEmbeddable;
import com.interview.mini_wsa.model.SecurityEventEntity;
import com.interview.mini_wsa.repository.SecurityEventRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.json.JsonMapper;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Normalizes an ingest payload into a flat list of events before enrichment.
 *
 * <p>The OpenAPI contract declares {@code event} / {@code events} as a {@code oneOf}, but the
 * generated model exposes both properties and enforces neither, so the exactly-one rule is
 * applied here.
 */
@Slf4j
@Service
public class ProcessingServiceImpl implements ProcessingService {

    private final WsaConfig wsaConfig;
    private final SecurityEventRepository securityEventRepository;
    private final JsonMapper jsonMapper;

    public ProcessingServiceImpl(WsaConfig wsaConfig,
                                 SecurityEventRepository securityEventRepository,
                                 JsonMapper jsonMapper) {
        this.wsaConfig = wsaConfig;
        this.securityEventRepository = securityEventRepository;
        this.jsonMapper = jsonMapper;
    }

    @Override
    @Transactional
    public void ingest(IngestRequest ingestRequest) {
        List<SecurityEvent> events = extractEvents(ingestRequest);
        log.debug("Processing {} security event(s)", events.size());
        OffsetDateTime now = OffsetDateTime.now();
        List<SecurityEventEntity> entities = events.stream()
                .map(event -> toEntity(event, now))
                .toList();

        securityEventRepository.saveAll(entities);
    }

    private SecurityEventEntity toEntity(SecurityEvent event, OffsetDateTime now) {
        SecurityEventEntity entity = new SecurityEventEntity();
        entity.setEventId(event.getEventId());
        entity.setTimestamp(event.getTimestamp());
        entity.setReceivedAt(now);
        entity.setConfigId(event.getConfigId().longValue());
        entity.setPolicyId(event.getPolicyId());
        entity.setClientIp(event.getClientIp());
        entity.setHostname(event.getHostname());
        entity.setPath(event.getPath());
        RuleEmbeddable ruleEntity = new RuleEmbeddable();
        Rule rule = event.getRule();
        Rule.CategoryEnum category = rule.getCategory();
        ruleEntity.setRuleId(asString(rule.getAdditionalProperty("ruleId")));
        ruleEntity.setName(asString(rule.getAdditionalProperty("name")));
        ruleEntity.setMessage(asString(rule.getAdditionalProperty("message")));
        ruleEntity.setCategory(category.name());
        ruleEntity.setSeverity(rule.getSeverity().name());
        entity.setRule(ruleEntity);
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

    private static String asString(Object value) {
        return value == null ? null : Objects.toString(value);
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
