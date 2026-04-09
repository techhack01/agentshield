-- AgentShield: Initial schema

CREATE TABLE IF NOT EXISTS agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    provider VARCHAR(50),
    status VARCHAR(20) DEFAULT 'active',
    policy JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    agent_id UUID REFERENCES agents(id),
    action VARCHAR(100) NOT NULL,
    tool_name VARCHAR(255),
    request_payload JSONB,
    response_summary TEXT,
    tokens_used INTEGER DEFAULT 0,
    latency_ms INTEGER,
    blocked BOOLEAN DEFAULT FALSE,
    block_reason TEXT,
    risk_score FLOAT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS violations (
    id BIGSERIAL PRIMARY KEY,
    agent_id UUID REFERENCES agents(id),
    audit_log_id BIGINT REFERENCES audit_log(id),
    violation_type VARCHAR(50),
    severity VARCHAR(20),
    details JSONB,
    mitre_technique VARCHAR(20),
    resolved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_agent ON audit_log(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_blocked ON audit_log(blocked) WHERE blocked = TRUE;
CREATE INDEX IF NOT EXISTS idx_violations_type ON violations(violation_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_violations_unresolved ON violations(resolved) WHERE resolved = FALSE;
