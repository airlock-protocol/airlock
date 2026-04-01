"""Tests for DomainMetrics Prometheus exposition."""

from airlock.gateway.metrics import DomainMetrics


class TestDomainMetrics:
    def test_revocations_counter(self):
        m = DomainMetrics()
        m.inc_revocations()
        m.inc_revocations()
        text = m.prometheus_domain_text()
        assert "airlock_revocations_total 2" in text

    def test_verdicts_by_type(self):
        m = DomainMetrics()
        m.inc_verdicts("VERIFIED")
        m.inc_verdicts("VERIFIED")
        m.inc_verdicts("REJECTED")
        text = m.prometheus_domain_text()
        assert 'airlock_verdicts_total{type="VERIFIED"} 2' in text
        assert 'airlock_verdicts_total{type="REJECTED"} 1' in text

    def test_challenges_by_outcome(self):
        m = DomainMetrics()
        m.inc_challenges("PASS")
        m.inc_challenges("FAIL")
        m.inc_challenges("PASS")
        text = m.prometheus_domain_text()
        assert 'airlock_challenges_total{outcome="PASS"} 2' in text
        assert 'airlock_challenges_total{outcome="FAIL"} 1' in text

    def test_delegations_counter(self):
        m = DomainMetrics()
        m.inc_delegations()
        text = m.prometheus_domain_text()
        assert "airlock_delegations_total 1" in text

    def test_audit_entries_counter(self):
        m = DomainMetrics()
        m.inc_audit_entries()
        m.inc_audit_entries()
        m.inc_audit_entries()
        text = m.prometheus_domain_text()
        assert "airlock_audit_entries_total 3" in text

    def test_empty_metrics(self):
        m = DomainMetrics()
        text = m.prometheus_domain_text()
        assert "airlock_revocations_total 0" in text
        assert "airlock_delegations_total 0" in text
        assert "airlock_audit_entries_total 0" in text
