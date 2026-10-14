package com.interview.mini_wsa.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Map;

@Configuration
@ConfigurationProperties(prefix = "mini-wsa")
@Data
public class WsaConfig {
    private Map<String,String> categories;
    private Map<String,Integer> severities;
    private Map<String,Integer> actions;
    private Integer sensitivePathsScore;
    private List<String> sensitivePaths;
    private List<WsaRule> rules;

    @Data
    public static class WsaRule {
        private int count;
        private int windowMinutes;
        private String matchingField;
        private int score;
    }
}
