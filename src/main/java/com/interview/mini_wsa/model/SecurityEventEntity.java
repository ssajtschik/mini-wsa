package com.interview.mini_wsa.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;

@Data
@Entity
@Table(
        name = "security_events",
        uniqueConstraints = {
                @UniqueConstraint(name = "unique_security_events_event_id", columnNames = {"event_id"})
        },
        indexes = {
                @Index(name = "idx_client_ip_timestamp", columnList = "client_ip, timestamp"),
                @Index(name = "idx_config_id", columnList = "config_id"),
                @Index(name = "idx_category", columnList = "category")
        }
)
public class SecurityEventEntity {

    @Id // Internal Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // External Id
    @Column(name = "event_id", nullable = false, unique = true)
    private String eventId;

    @Column(name = "timestamp", nullable = false)
    private OffsetDateTime timestamp;

    @Column(name = "received_at", nullable = false)
    private OffsetDateTime receivedAt;

    @Column(name = "config_id", nullable = false)
    private Long configId;

    @Column(name = "policy_id", nullable = false)
    private String policyId;

    @Column(name = "client_ip", nullable = false)
    private String clientIp;

    @Column(name = "hostname", nullable = false)
    private String hostname;

    @Column(name = "path", nullable = false)
    private String path;

    @Column(name = "action", nullable = false)
    private String action;

    @Column(name = "attack_type", nullable = false)
    private String attackType;

    @Column(name = "threat_score", nullable = false)
    @NotNull(message = "Threat score is required")
    @Min(value = 1, message = "Threat score must be at least 1")
    @Max(value = 100, message = "Threat score cannot exceed 100")
    private int threatScore;

    @Embedded
    private RuleEmbeddable rule;

    @Column(name = "raw_payload", columnDefinition = "jsonb", nullable = false)
    @JdbcTypeCode(SqlTypes.JSON)
    private String rawPayload;
}