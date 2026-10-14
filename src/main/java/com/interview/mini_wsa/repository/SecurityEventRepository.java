package com.interview.mini_wsa.repository;

import com.interview.mini_wsa.model.SecurityEventEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEventEntity, Long>,
        JpaSpecificationExecutor<SecurityEventEntity>, SecurityEventStatsRepository {
}
