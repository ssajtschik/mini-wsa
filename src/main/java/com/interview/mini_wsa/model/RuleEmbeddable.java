package com.interview.mini_wsa.model;

import jakarta.persistence.Embeddable;
import lombok.Data;

@Data
@Embeddable
public class RuleEmbeddable {
    private String ruleId;
    private String name;
    private String message;
    private String severity;
    private String category;
}