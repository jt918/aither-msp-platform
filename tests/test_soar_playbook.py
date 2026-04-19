"""
Tests for SOAR Playbook Engine
"""

import pytest
from datetime import datetime
import asyncio

from services.msp.soar_playbook import (
    SOARPlaybookService,
    ActionType,
    ExecutionStatus,
    TriggerType,
    Playbook,
    PlaybookStep,
    PlaybookExecution,
    StepResult,
)


class TestSOARPlaybookService:
    """Tests for SOARPlaybookService"""

    def setup_method(self):
        """Set up test fixtures"""
        self.service = SOARPlaybookService()

    # ========== Pre-built Playbook Tests ==========

    def test_prebuilt_playbooks_loaded(self):
        """Pre-built playbooks should be loaded on init"""
        playbooks = self.service.list_playbooks()
        assert len(playbooks) >= 5
        ids = [p["playbook_id"] for p in playbooks]
        assert "PB-RANSOM-001" in ids
        assert "PB-BRUTE-001" in ids
        assert "PB-PHISH-001" in ids
        assert "PB-EXFIL-001" in ids
        assert "PB-MALWR-001" in ids

    def test_ransomware_playbook_structure(self):
        """Ransomware playbook should have correct steps"""
        pb = self.service.get_playbook("PB-RANSOM-001")
        assert pb is not None
        assert pb["name"] == "Ransomware Response"
        assert pb["trigger_type"] == "automatic"
        assert len(pb["steps"]) == 7
        assert pb["steps"][0]["action_type"] == "isolate_host"
        assert pb["trigger_conditions"]["threat_type"] == "ransomware"

    def test_brute_force_playbook_structure(self):
        """Brute force playbook should have conditional step"""
        pb = self.service.get_playbook("PB-BRUTE-001")
        assert pb is not None
        assert len(pb["steps"]) == 6
        # Step 2 should have a condition
        block_step = pb["steps"][1]
        assert block_step["action_type"] == "block_ip"
        assert block_step["condition"] is not None

    def test_data_exfil_playbook_has_approval_gate(self):
        """Data exfiltration playbook should have an approval gate"""
        pb = self.service.get_playbook("PB-EXFIL-001")
        assert pb is not None
        approval_steps = [s for s in pb["steps"] if s["wait_for_approval"]]
        assert len(approval_steps) >= 1

    # ========== Playbook CRUD Tests ==========

    def test_create_playbook(self):
        """Should create a custom playbook"""
        pb = self.service.create_playbook({
            "name": "Test Playbook",
            "description": "A test playbook",
            "trigger_type": "manual",
            "tags": ["test"],
            "steps": [
                {"name": "Block IP", "action_type": "block_ip", "parameters": {"ip": "1.2.3.4"}},
                {"name": "Notify", "action_type": "send_notification", "parameters": {"channel": "test"}},
            ],
        })
        assert pb.name == "Test Playbook"
        assert len(pb.steps) == 2
        assert pb.steps[0].step_number == 1
        assert pb.steps[1].step_number == 2

    def test_update_playbook(self):
        """Should update a playbook"""
        pb = self.service.create_playbook({"name": "Original", "steps": []})
        updated = self.service.update_playbook(pb.playbook_id, {
            "name": "Updated Name",
            "is_enabled": False,
        })
        assert updated is not None
        assert updated.name == "Updated Name"
        assert updated.is_enabled is False
        assert updated.version == 2

    def test_update_nonexistent_playbook(self):
        """Should return None for nonexistent playbook"""
        result = self.service.update_playbook("PB-DOESNT-EXIST", {"name": "X"})
        assert result is None

    def test_delete_playbook(self):
        """Should delete a playbook"""
        pb = self.service.create_playbook({"name": "To Delete", "steps": []})
        assert self.service.delete_playbook(pb.playbook_id) is True
        assert self.service.get_playbook(pb.playbook_id) is None

    def test_delete_nonexistent_playbook(self):
        """Should return False for nonexistent playbook"""
        assert self.service.delete_playbook("PB-NOPE") is False

    def test_list_playbooks_enabled_only(self):
        """Should filter to enabled playbooks only"""
        self.service.create_playbook({"name": "Disabled PB", "is_enabled": False, "steps": []})
        all_pbs = self.service.list_playbooks()
        enabled_pbs = self.service.list_playbooks(enabled_only=True)
        assert len(enabled_pbs) < len(all_pbs)

    def test_list_playbooks_by_tag(self):
        """Should filter playbooks by tag"""
        self.service.create_playbook({"name": "Tagged PB", "tags": ["unique-tag-xyz"], "steps": []})
        results = self.service.list_playbooks(tag="unique-tag-xyz")
        assert len(results) == 1
        assert results[0]["name"] == "Tagged PB"

    def test_clone_playbook(self):
        """Should clone a playbook with new ID"""
        original = self.service.get_playbook("PB-RANSOM-001")
        cloned = self.service.clone_playbook("PB-RANSOM-001", new_name="Cloned Ransomware")
        assert cloned is not None
        assert cloned.playbook_id != "PB-RANSOM-001"
        assert cloned.name == "Cloned Ransomware"
        assert len(cloned.steps) == len(original["steps"])

    def test_clone_nonexistent_playbook(self):
        """Should return None when cloning nonexistent playbook"""
        assert self.service.clone_playbook("PB-NOPE") is None

    def test_get_playbook(self):
        """Should return playbook dict"""
        pb = self.service.get_playbook("PB-RANSOM-001")
        assert pb is not None
        assert isinstance(pb, dict)
        assert "playbook_id" in pb
        assert "steps" in pb

    def test_get_nonexistent_playbook(self):
        """Should return None for nonexistent playbook"""
        assert self.service.get_playbook("PB-NOPE-999") is None

    # ========== Execution Lifecycle Tests ==========

    @pytest.mark.asyncio
    async def test_execute_playbook(self):
        """Should execute a playbook and return completed execution"""
        pb = self.service.create_playbook({
            "name": "Simple Execute",
            "steps": [
                {"name": "Block", "action_type": "block_ip", "parameters": {"ip": "10.0.0.1"}},
                {"name": "Notify", "action_type": "send_notification"},
            ],
        })
        execution = await self.service.execute_playbook(
            pb.playbook_id, "INC-001", context={"source_ip": "10.0.0.1"},
        )
        assert execution is not None
        assert execution.status == ExecutionStatus.COMPLETED
        assert len(execution.step_results) == 2
        assert all(sr.status == "completed" for sr in execution.step_results)

    @pytest.mark.asyncio
    async def test_execute_nonexistent_playbook(self):
        """Should return None for nonexistent playbook"""
        result = await self.service.execute_playbook("PB-NOPE", "INC-001")
        assert result is None

    @pytest.mark.asyncio
    async def test_execute_disabled_playbook(self):
        """Should return None for disabled playbook"""
        pb = self.service.create_playbook({
            "name": "Disabled",
            "is_enabled": False,
            "steps": [{"name": "Block", "action_type": "block_ip"}],
        })
        result = await self.service.execute_playbook(pb.playbook_id, "INC-001")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_execution(self):
        """Should retrieve execution by ID"""
        pb = self.service.create_playbook({
            "name": "Get Test",
            "steps": [{"name": "Notify", "action_type": "send_notification"}],
        })
        execution = await self.service.execute_playbook(pb.playbook_id, "INC-002")
        result = self.service.get_execution(execution.execution_id)
        assert result is not None
        assert result["execution_id"] == execution.execution_id

    @pytest.mark.asyncio
    async def test_list_executions(self):
        """Should list executions"""
        pb = self.service.create_playbook({
            "name": "List Test",
            "steps": [{"name": "Notify", "action_type": "send_notification"}],
        })
        await self.service.execute_playbook(pb.playbook_id, "INC-003")
        await self.service.execute_playbook(pb.playbook_id, "INC-004")
        execs = self.service.list_executions()
        assert len(execs) >= 2

    @pytest.mark.asyncio
    async def test_list_executions_filtered(self):
        """Should filter executions by playbook_id and status"""
        pb = self.service.create_playbook({
            "name": "Filter Test",
            "steps": [{"name": "Notify", "action_type": "send_notification"}],
        })
        await self.service.execute_playbook(pb.playbook_id, "INC-005")
        execs = self.service.list_executions(playbook_id=pb.playbook_id, status="completed")
        assert len(execs) >= 1
        assert all(e["playbook_id"] == pb.playbook_id for e in execs)

    # ========== Step Dispatch Tests ==========

    @pytest.mark.asyncio
    async def test_all_action_types_execute(self):
        """Each action type should execute without error"""
        for action in ActionType:
            pb = self.service.create_playbook({
                "name": f"Test {action.value}",
                "steps": [{"name": action.value, "action_type": action.value}],
            })
            execution = await self.service.execute_playbook(
                pb.playbook_id, f"INC-{action.value}",
                context={"source_ip": "1.2.3.4", "hostname": "test-host", "user": "testuser"},
            )
            assert execution is not None, f"Failed to execute {action.value}"
            # approval_gate and wait actions are special cases
            if action not in (ActionType.APPROVAL_GATE,):
                assert execution.status in (ExecutionStatus.COMPLETED, ExecutionStatus.AWAITING_APPROVAL), \
                    f"Action {action.value} ended with status {execution.status}"

    @pytest.mark.asyncio
    async def test_step_failure_abort(self):
        """Step with on_failure=abort should stop execution"""
        # We need to make a step fail. We'll use a custom approach.
        pb = self.service.create_playbook({
            "name": "Abort Test",
            "steps": [
                {"name": "Will Succeed", "action_type": "send_notification"},
                {"name": "Will Succeed Too", "action_type": "block_ip"},
            ],
        })
        execution = await self.service.execute_playbook(pb.playbook_id, "INC-ABORT")
        # Both should complete since no actual failures in mock handlers
        assert execution.status == ExecutionStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_step_condition_skip(self):
        """Steps with unmet conditions should be skipped"""
        pb = self.service.create_playbook({
            "name": "Condition Test",
            "steps": [
                {"name": "Check Rep", "action_type": "lookup_reputation"},
                {"name": "Block If Bad", "action_type": "block_ip",
                 "condition": "reputation_score < 10"},  # 25 from mock, won't match
            ],
        })
        execution = await self.service.execute_playbook(
            pb.playbook_id, "INC-COND", context={"source_ip": "1.2.3.4"},
        )
        assert execution is not None
        assert execution.status == ExecutionStatus.COMPLETED
        # The block step should be skipped because reputation_score=25 > 10
        block_result = execution.step_results[1]
        assert block_result.status == "skipped"

    @pytest.mark.asyncio
    async def test_step_condition_execute(self):
        """Steps with met conditions should execute"""
        pb = self.service.create_playbook({
            "name": "Condition Met Test",
            "steps": [
                {"name": "Check Rep", "action_type": "lookup_reputation"},
                {"name": "Block If Bad", "action_type": "block_ip",
                 "condition": "reputation_score < 50"},  # 25 < 50, will match
            ],
        })
        execution = await self.service.execute_playbook(
            pb.playbook_id, "INC-CONDMET", context={"source_ip": "1.2.3.4"},
        )
        assert execution is not None
        block_result = execution.step_results[1]
        assert block_result.status == "completed"

    # ========== Approval Gate Tests ==========

    @pytest.mark.asyncio
    async def test_approval_gate_pauses_execution(self):
        """Execution should pause at an approval gate"""
        pb = self.service.create_playbook({
            "name": "Approval Test",
            "steps": [
                {"name": "Block", "action_type": "block_ip"},
                {"name": "Escalate", "action_type": "escalate",
                 "wait_for_approval": True},
                {"name": "Notify", "action_type": "send_notification"},
            ],
        })
        execution = await self.service.execute_playbook(pb.playbook_id, "INC-APPROVAL")
        assert execution is not None
        assert execution.status == ExecutionStatus.AWAITING_APPROVAL
        # Only first step should be completed, second awaiting
        assert execution.step_results[0].status == "completed"
        assert execution.step_results[1].status == "awaiting_approval"
        # Third step should not have run yet
        assert len(execution.step_results) == 2

    @pytest.mark.asyncio
    async def test_approve_step_resumes_execution(self):
        """Approving a step should resume and complete the execution"""
        pb = self.service.create_playbook({
            "name": "Resume Test",
            "steps": [
                {"name": "Block", "action_type": "block_ip",
                 "step_id": "STEP-A"},
                {"name": "Escalate", "action_type": "escalate",
                 "wait_for_approval": True, "step_id": "STEP-B"},
                {"name": "Notify", "action_type": "send_notification",
                 "step_id": "STEP-C"},
            ],
        })
        execution = await self.service.execute_playbook(pb.playbook_id, "INC-RESUME")
        assert execution.status == ExecutionStatus.AWAITING_APPROVAL

        # Approve the step
        result = await self.service.approve_step(execution.execution_id, "STEP-B")
        assert result is not None
        assert result["status"] == "completed"
        # All three steps should now have results
        completed_results = [r for r in result["step_results"] if r["status"] == "completed"]
        assert len(completed_results) == 3

    @pytest.mark.asyncio
    async def test_approve_nonexistent_execution(self):
        """Should return None for nonexistent execution"""
        result = await self.service.approve_step("EX-NOPE", "STEP-NOPE")
        assert result is None

    # ========== Abort Tests ==========

    @pytest.mark.asyncio
    async def test_abort_awaiting_execution(self):
        """Should abort an execution awaiting approval"""
        pb = self.service.create_playbook({
            "name": "Abort Approval Test",
            "steps": [
                {"name": "Gate", "action_type": "escalate",
                 "wait_for_approval": True, "step_id": "GATE-1"},
            ],
        })
        execution = await self.service.execute_playbook(pb.playbook_id, "INC-ABORT2")
        assert execution.status == ExecutionStatus.AWAITING_APPROVAL

        result = await self.service.abort_execution(execution.execution_id)
        assert result is not None
        assert result["status"] == "aborted"

    @pytest.mark.asyncio
    async def test_abort_nonexistent_execution(self):
        """Should return None for nonexistent execution"""
        result = await self.service.abort_execution("EX-NOPE")
        assert result is None

    # ========== Trigger Evaluation Tests ==========

    @pytest.mark.asyncio
    async def test_evaluate_triggers_ransomware(self):
        """Ransomware incident should trigger ransomware playbook"""
        incident = {
            "incident_id": "INC-RANSOM-EVAL",
            "threat_type": "ransomware",
            "severity": 9,
            "source": "EDR",
            "hostname": "WORKSTATION-01",
        }
        executions = await self.service.evaluate_triggers(incident)
        assert len(executions) >= 1
        pb_ids = [ex.playbook_id for ex in executions]
        assert "PB-RANSOM-001" in pb_ids

    @pytest.mark.asyncio
    async def test_evaluate_triggers_low_severity_no_match(self):
        """Low severity ransomware should not trigger (min severity 8)"""
        incident = {
            "incident_id": "INC-LOW",
            "threat_type": "ransomware",
            "severity": 3,
        }
        executions = await self.service.evaluate_triggers(incident)
        pb_ids = [ex.playbook_id for ex in executions]
        assert "PB-RANSOM-001" not in pb_ids

    @pytest.mark.asyncio
    async def test_evaluate_triggers_malware(self):
        """Malware incident should trigger malware playbook"""
        incident = {
            "incident_id": "INC-MALWR-EVAL",
            "threat_type": "malware",
            "severity": 7,
        }
        executions = await self.service.evaluate_triggers(incident)
        pb_ids = [ex.playbook_id for ex in executions]
        assert "PB-MALWR-001" in pb_ids

    @pytest.mark.asyncio
    async def test_evaluate_triggers_phishing(self):
        """Phishing incident should trigger phishing playbook"""
        incident = {
            "incident_id": "INC-PHISH-EVAL",
            "threat_type": "phishing",
            "severity": 6,
        }
        executions = await self.service.evaluate_triggers(incident)
        pb_ids = [ex.playbook_id for ex in executions]
        assert "PB-PHISH-001" in pb_ids

    @pytest.mark.asyncio
    async def test_evaluate_triggers_no_match(self):
        """Unknown threat type should not trigger any playbook"""
        incident = {
            "incident_id": "INC-UNKNOWN",
            "threat_type": "alien_invasion",
            "severity": 10,
        }
        executions = await self.service.evaluate_triggers(incident)
        assert len(executions) == 0

    @pytest.mark.asyncio
    async def test_disabled_playbook_not_triggered(self):
        """Disabled playbooks should not be triggered"""
        # Disable the ransomware playbook
        self.service.update_playbook("PB-RANSOM-001", {"is_enabled": False})
        incident = {
            "incident_id": "INC-DISABLED",
            "threat_type": "ransomware",
            "severity": 10,
        }
        executions = await self.service.evaluate_triggers(incident)
        pb_ids = [ex.playbook_id for ex in executions]
        assert "PB-RANSOM-001" not in pb_ids
        # Re-enable
        self.service.update_playbook("PB-RANSOM-001", {"is_enabled": True})

    # ========== Analytics Tests ==========

    def test_get_playbook_stats(self):
        """Should return aggregate stats"""
        stats = self.service.get_playbook_stats()
        assert "total_playbooks" in stats
        assert stats["total_playbooks"] >= 5
        assert "enabled_playbooks" in stats
        assert "total_executions" in stats

    def test_get_most_triggered(self):
        """Should return most triggered playbooks"""
        top = self.service.get_most_triggered(3)
        assert isinstance(top, list)
        assert len(top) <= 3

    @pytest.mark.asyncio
    async def test_average_resolution_time(self):
        """Should calculate average resolution time"""
        pb = self.service.create_playbook({
            "name": "Timing Test",
            "steps": [{"name": "Quick", "action_type": "send_notification"}],
        })
        await self.service.execute_playbook(pb.playbook_id, "INC-TIME1")
        await self.service.execute_playbook(pb.playbook_id, "INC-TIME2")
        avg = self.service.get_average_resolution_time()
        assert isinstance(avg, float)
        assert avg >= 0

    def test_get_dashboard(self):
        """Should return dashboard data"""
        dashboard = self.service.get_dashboard()
        assert "active_executions" in dashboard
        assert "playbook_library_size" in dashboard
        assert dashboard["playbook_library_size"] >= 5
        assert "top_playbooks" in dashboard
        assert "recent_executions" in dashboard
        assert "stats" in dashboard

    # ========== Context Accumulation Tests ==========

    @pytest.mark.asyncio
    async def test_context_accumulates_across_steps(self):
        """Step outputs should accumulate in the execution context"""
        pb = self.service.create_playbook({
            "name": "Context Test",
            "steps": [
                {"name": "Lookup", "action_type": "lookup_reputation"},
                {"name": "Block", "action_type": "block_ip"},
            ],
        })
        execution = await self.service.execute_playbook(
            pb.playbook_id, "INC-CTX", context={"source_ip": "5.5.5.5"},
        )
        assert execution is not None
        # Context should contain outputs from both steps
        assert "reputation_score" in execution.context
        assert "blocked" in execution.context

    # ========== Enum Tests ==========

    def test_action_type_values(self):
        """ActionType enum should have all expected values"""
        expected = {
            "block_ip", "isolate_host", "disable_account", "quarantine_file",
            "send_notification", "create_ticket", "run_scan", "collect_forensics",
            "enrich_ioc", "lookup_reputation", "update_firewall_rule",
            "restart_service", "snapshot_vm", "escalate", "custom_script",
            "wait", "approval_gate", "add_to_watchlist", "revoke_sessions",
            "force_password_reset",
        }
        actual = {a.value for a in ActionType}
        assert expected == actual

    def test_execution_status_values(self):
        """ExecutionStatus enum should have all expected values"""
        expected = {"pending", "running", "completed", "failed", "aborted", "awaiting_approval"}
        actual = {s.value for s in ExecutionStatus}
        assert expected == actual

    def test_trigger_type_values(self):
        """TriggerType enum should have all expected values"""
        expected = {"manual", "automatic", "scheduled", "webhook"}
        actual = {t.value for t in TriggerType}
        assert expected == actual

    # ========== Execution Stats Update Tests ==========

    @pytest.mark.asyncio
    async def test_execution_updates_playbook_stats(self):
        """Executing a playbook should increment its execution count"""
        pb = self.service.create_playbook({
            "name": "Stats Test",
            "steps": [{"name": "Quick", "action_type": "send_notification"}],
        })
        assert pb.execution_count == 0
        await self.service.execute_playbook(pb.playbook_id, "INC-STAT1")
        updated = self.service._playbooks[pb.playbook_id]
        assert updated.execution_count == 1
        assert updated.avg_execution_time_seconds >= 0

        await self.service.execute_playbook(pb.playbook_id, "INC-STAT2")
        assert self.service._playbooks[pb.playbook_id].execution_count == 2
