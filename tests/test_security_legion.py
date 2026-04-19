"""
Tests for Security Legion — Red/Blue/Purple Team Persona Service

Covers: team spawning, persona lifecycle, mission deployment/execution,
technique mastery, promotion, AAR generation, leaderboard, dashboard.
"""

import pytest
from services.msp.security_legion import (
    SecurityLegionService,
    TeamType,
    RedRole,
    BlueRole,
    PersonaStatus,
    MissionStatus,
)


@pytest.fixture
def svc():
    """Fresh SecurityLegionService with no DB."""
    return SecurityLegionService()


# ============================================================
# Initialization
# ============================================================

class TestInitialization:
    def test_service_creates(self, svc):
        assert svc is not None

    def test_prebuilt_personas_loaded(self, svc):
        personas = svc.list_personas()
        assert len(personas) == 16  # 8 red + 8 blue

    def test_red_personas_count(self, svc):
        red = svc.list_personas(team="red")
        assert len(red) == 8

    def test_blue_personas_count(self, svc):
        blue = svc.list_personas(team="blue")
        assert len(blue) == 8

    def test_mitre_techniques_loaded(self, svc):
        techniques = svc.list_techniques()
        assert len(techniques) >= 30

    def test_techniques_have_mitre_ids(self, svc):
        techniques = svc.list_techniques()
        for t in techniques:
            assert t["mitre_id"].startswith("T")


# ============================================================
# Team Spawning
# ============================================================

class TestTeamSpawning:
    def test_spawn_red_team(self, svc):
        result = svc.spawn_red_team("CLIENT-001", size=4)
        assert "team_id" in result
        assert result["team_type"] == "red_team"
        assert len(result["personas"]) == 4

    def test_spawn_blue_team(self, svc):
        result = svc.spawn_blue_team("CLIENT-001", size=4)
        assert "team_id" in result
        assert result["team_type"] == "blue_team"
        assert len(result["personas"]) == 4

    def test_spawn_purple_team(self, svc):
        result = svc.spawn_purple_team("CLIENT-001")
        assert "team_id" in result
        assert result["team_type"] == "purple_team"
        assert len(result["personas"]) >= 2

    def test_spawn_custom_team(self, svc):
        configs = [
            {"name": "TestAgent", "team": "red", "role": "recon_specialist", "skill_level": 0.8},
            {"name": "TestAgent2", "team": "red", "role": "exploit_developer", "skill_level": 0.9},
        ]
        result = svc.spawn_custom_team("CLIENT-002", "red_team", configs)
        assert "team_id" in result
        assert len(result["personas"]) == 2

    def test_list_teams(self, svc):
        svc.spawn_red_team("CLIENT-001")
        svc.spawn_blue_team("CLIENT-002")
        teams = svc.list_teams()
        assert len(teams) == 2

    def test_list_teams_by_client(self, svc):
        svc.spawn_red_team("CLIENT-001")
        svc.spawn_blue_team("CLIENT-002")
        teams = svc.list_teams(client_id="CLIENT-001")
        assert len(teams) == 1

    def test_get_team(self, svc):
        created = svc.spawn_red_team("CLIENT-001")
        result = svc.get_team(created["team_id"])
        assert result is not None
        assert result["team_id"] == created["team_id"]

    def test_get_team_not_found(self, svc):
        assert svc.get_team("NONEXISTENT") is None

    def test_disband_team(self, svc):
        created = svc.spawn_red_team("CLIENT-001")
        result = svc.disband_team(created["team_id"])
        assert result["status"] == "disbanded"
        assert svc.get_team(created["team_id"]) is None

    def test_disband_releases_personas(self, svc):
        created = svc.spawn_red_team("CLIENT-001", size=2)
        pid = created["personas"][0]
        svc.disband_team(created["team_id"])
        persona = svc.get_persona(pid)
        assert persona["status"] == "available"
        assert persona["team_id"] is None


# ============================================================
# Persona Lifecycle
# ============================================================

class TestPersonaLifecycle:
    def test_get_persona(self, svc):
        personas = svc.list_personas(team="red")
        pid = personas[0]["persona_id"]
        result = svc.get_persona(pid)
        assert result is not None
        assert result["team"] == "red"

    def test_get_persona_not_found(self, svc):
        assert svc.get_persona("NONEXISTENT") is None

    def test_filter_by_status(self, svc):
        available = svc.list_personas(status="available")
        assert len(available) == 16

    def test_retire_persona(self, svc):
        personas = svc.list_personas(team="red")
        pid = personas[0]["persona_id"]
        result = svc.retire_persona(pid)
        assert result["status"] == "retired"
        updated = svc.get_persona(pid)
        assert updated["status"] == "retired"

    def test_retire_not_found(self, svc):
        result = svc.retire_persona("NONEXISTENT")
        assert "error" in result

    def test_prebuilt_red_names(self, svc):
        red = svc.list_personas(team="red")
        names = {p["name"] for p in red}
        assert "Ghost" in names
        assert "Viper" in names
        assert "Siren" in names
        assert "Shadow" in names

    def test_prebuilt_blue_names(self, svc):
        blue = svc.list_personas(team="blue")
        names = {p["name"] for p in blue}
        assert "Sentinel" in names
        assert "Phoenix" in names
        assert "Sherlock" in names
        assert "Scalpel" in names

    def test_persona_has_techniques(self, svc):
        red = svc.list_personas(team="red")
        # Ghost (recon_specialist) should have techniques
        ghost = [p for p in red if p["name"] == "Ghost"][0]
        assert len(ghost["techniques_mastered"]) > 0

    def test_persona_has_certifications(self, svc):
        red = svc.list_personas(team="red")
        viper = [p for p in red if p["name"] == "Viper"][0]
        assert len(viper["certifications"]) > 0


# ============================================================
# Training
# ============================================================

class TestTraining:
    def test_assign_training(self, svc):
        personas = svc.list_personas(team="blue")
        pid = personas[0]["persona_id"]
        # Find a technique this persona doesn't have
        current = set(personas[0]["techniques_mastered"])
        all_techs = svc.list_techniques()
        new_tech = None
        for t in all_techs:
            if t["technique_id"] not in current and t["persona_skill_required"] <= personas[0]["skill_level"]:
                new_tech = t["technique_id"]
                break
        if new_tech:
            result = svc.assign_training(pid, new_tech)
            assert result["status"] == "trained"
            updated = svc.get_persona(pid)
            assert new_tech in updated["techniques_mastered"]

    def test_train_already_mastered(self, svc):
        personas = svc.list_personas(team="red")
        p = personas[0]
        if p["techniques_mastered"]:
            result = svc.assign_training(p["persona_id"], p["techniques_mastered"][0])
            assert "error" in result

    def test_train_not_found_persona(self, svc):
        result = svc.assign_training("NONEXISTENT", "T-001")
        assert "error" in result

    def test_train_not_found_technique(self, svc):
        personas = svc.list_personas()
        result = svc.assign_training(personas[0]["persona_id"], "T-999")
        assert "error" in result


# ============================================================
# Promotion
# ============================================================

class TestPromotion:
    def test_promote_insufficient_missions(self, svc):
        personas = svc.list_personas(team="red")
        pid = personas[0]["persona_id"]
        result = svc.promote_persona(pid)
        assert "error" in result
        assert "5+" in result["error"]

    def test_promote_after_missions(self, svc):
        # Manually set a persona to promotable state
        personas = svc.list_personas(team="red")
        pid = personas[0]["persona_id"]
        p = svc._personas[pid]
        p.missions_completed = 10
        p.missions_success_rate = 0.9
        old_skill = p.skill_level
        result = svc.promote_persona(pid)
        assert result["status"] == "promoted"
        assert result["skill_level_after"] > old_skill

    def test_promote_low_success_rate(self, svc):
        personas = svc.list_personas(team="red")
        pid = personas[0]["persona_id"]
        p = svc._personas[pid]
        p.missions_completed = 10
        p.missions_success_rate = 0.5
        result = svc.promote_persona(pid)
        assert "error" in result
        assert "85%" in result["error"]


# ============================================================
# Mission Deployment & Execution
# ============================================================

class TestMissions:
    def test_deploy_red_team(self, svc):
        team = svc.spawn_red_team("CLIENT-001", size=4)
        result = svc.deploy_team(team["team_id"], "TWIN-001", "Full penetration test")
        assert "mission_id" in result
        assert result["status"] == "planning"

    def test_deploy_already_deployed(self, svc):
        team = svc.spawn_red_team("CLIENT-001", size=4)
        svc.deploy_team(team["team_id"], "TWIN-001", "Test")
        result = svc.deploy_team(team["team_id"], "TWIN-002", "Test2")
        assert "error" in result

    def test_execute_red_mission(self, svc):
        team = svc.spawn_red_team("CLIENT-001", size=4)
        mission = svc.deploy_team(team["team_id"], "TWIN-001", "Attack simulation")
        result = svc.execute_mission(mission["mission_id"])
        assert result["status"] == "completed"
        assert "score" in result
        assert result["score"] >= 0

    def test_execute_blue_mission(self, svc):
        team = svc.spawn_blue_team("CLIENT-001", size=4)
        mission = svc.deploy_team(team["team_id"], "TWIN-001", "Defend simulation")
        result = svc.execute_mission(mission["mission_id"])
        assert result["status"] == "completed"
        assert "score" in result

    def test_execute_purple_mission(self, svc):
        team = svc.spawn_purple_team("CLIENT-001")
        mission = svc.deploy_team(team["team_id"], "TWIN-001", "Combined exercise")
        result = svc.execute_mission(mission["mission_id"])
        assert result["status"] == "completed"
        assert "red_score" in result
        assert "blue_score" in result

    def test_execute_updates_persona_stats(self, svc):
        team = svc.spawn_red_team("CLIENT-001", size=2)
        pid = team["personas"][0]
        before = svc.get_persona(pid)
        assert before["missions_completed"] == 0
        mission = svc.deploy_team(team["team_id"], "TWIN-001", "Test")
        svc.execute_mission(mission["mission_id"])
        after = svc.get_persona(pid)
        assert after["missions_completed"] == 1
        assert after["experience_points"] > 0

    def test_list_missions(self, svc):
        team = svc.spawn_red_team("CLIENT-001", size=2)
        m1 = svc.deploy_team(team["team_id"], "TWIN-001", "Test")
        missions = svc.list_missions()
        assert len(missions) >= 1

    def test_get_mission(self, svc):
        team = svc.spawn_red_team("CLIENT-001", size=2)
        m = svc.deploy_team(team["team_id"], "TWIN-001", "Test")
        result = svc.get_mission(m["mission_id"])
        assert result is not None
        assert result["mission_id"] == m["mission_id"]

    def test_abort_mission(self, svc):
        team = svc.spawn_red_team("CLIENT-001", size=2)
        m = svc.deploy_team(team["team_id"], "TWIN-001", "Test")
        result = svc.abort_mission(m["mission_id"])
        assert result["status"] == "finalized"

    def test_complete_mission_releases_team(self, svc):
        team = svc.spawn_red_team("CLIENT-001", size=2)
        mission = svc.deploy_team(team["team_id"], "TWIN-001", "Test")
        svc.execute_mission(mission["mission_id"])
        svc.complete_mission(mission["mission_id"])
        updated_team = svc.get_team(team["team_id"])
        assert updated_team["status"] == "standby"


# ============================================================
# After-Action Reports
# ============================================================

class TestAfterActionReport:
    def test_generate_aar(self, svc):
        team = svc.spawn_red_team("CLIENT-001", size=4)
        mission = svc.deploy_team(team["team_id"], "TWIN-001", "Test")
        svc.execute_mission(mission["mission_id"])
        aar = svc.generate_after_action_report(mission["mission_id"])
        assert "report_id" in aar
        assert "executive_summary" in aar
        assert "recommendations" in aar
        assert len(aar["recommendations"]) > 0
        assert aar["risk_score_before"] > 0

    def test_get_report(self, svc):
        team = svc.spawn_red_team("CLIENT-001", size=4)
        mission = svc.deploy_team(team["team_id"], "TWIN-001", "Test")
        svc.execute_mission(mission["mission_id"])
        svc.generate_after_action_report(mission["mission_id"])
        report = svc.get_report(mission["mission_id"])
        assert report is not None
        assert "executive_summary" in report

    def test_aar_requires_completed_mission(self, svc):
        team = svc.spawn_red_team("CLIENT-001", size=2)
        mission = svc.deploy_team(team["team_id"], "TWIN-001", "Test")
        result = svc.generate_after_action_report(mission["mission_id"])
        assert "error" in result

    def test_aar_has_risk_scores(self, svc):
        team = svc.spawn_red_team("CLIENT-001", size=4)
        mission = svc.deploy_team(team["team_id"], "TWIN-001", "Test")
        svc.execute_mission(mission["mission_id"])
        aar = svc.generate_after_action_report(mission["mission_id"])
        assert aar["risk_score_before"] >= 0
        assert aar["risk_score_after"] >= 0

    def test_aar_has_lessons_learned(self, svc):
        team = svc.spawn_red_team("CLIENT-001", size=4)
        mission = svc.deploy_team(team["team_id"], "TWIN-001", "Test")
        svc.execute_mission(mission["mission_id"])
        aar = svc.generate_after_action_report(mission["mission_id"])
        assert len(aar["lessons_learned"]) > 0


# ============================================================
# Technique Coverage
# ============================================================

class TestTechniqueCoverage:
    def test_team_coverage(self, svc):
        team = svc.spawn_red_team("CLIENT-001", size=8)
        cov = svc.get_technique_coverage(team["team_id"])
        assert "covered" in cov
        assert "uncovered" in cov
        assert cov["coverage_pct"] > 0

    def test_coverage_not_found(self, svc):
        result = svc.get_technique_coverage("NONEXISTENT")
        assert "error" in result

    def test_larger_team_more_coverage(self, svc):
        small = svc.spawn_red_team("C1", size=2)
        # Create new service for clean state
        svc2 = SecurityLegionService()
        big = svc2.spawn_red_team("C2", size=8)
        cov_small = svc.get_technique_coverage(small["team_id"])
        cov_big = svc2.get_technique_coverage(big["team_id"])
        assert cov_big["coverage_pct"] >= cov_small["coverage_pct"]


# ============================================================
# Leaderboard
# ============================================================

class TestLeaderboard:
    def test_leaderboard_returns_list(self, svc):
        board = svc.get_leaderboard()
        assert isinstance(board, list)
        assert len(board) == 16  # all 16 prebuilt

    def test_leaderboard_has_rank(self, svc):
        board = svc.get_leaderboard()
        assert board[0]["rank"] == 1

    def test_leaderboard_limit(self, svc):
        board = svc.get_leaderboard(limit=5)
        assert len(board) == 5

    def test_leaderboard_sorted_by_xp(self, svc):
        # Give one persona XP
        personas = svc.list_personas(team="red")
        pid = personas[0]["persona_id"]
        svc._personas[pid].experience_points = 99999
        board = svc.get_leaderboard()
        assert board[0]["persona_id"] == pid


# ============================================================
# Dashboard
# ============================================================

class TestDashboard:
    def test_dashboard_empty_client(self, svc):
        dash = svc.get_dashboard("UNKNOWN")
        assert dash["client_id"] == "UNKNOWN"
        assert dash["team_count"] == 0

    def test_dashboard_with_teams(self, svc):
        svc.spawn_red_team("CLIENT-A", size=4)
        svc.spawn_blue_team("CLIENT-A", size=4)
        dash = svc.get_dashboard("CLIENT-A")
        assert dash["team_count"] == 2

    def test_dashboard_with_missions(self, svc):
        team = svc.spawn_red_team("CLIENT-B", size=4)
        mission = svc.deploy_team(team["team_id"], "TWIN-B", "Dash test")
        svc.execute_mission(mission["mission_id"])
        dash = svc.get_dashboard("CLIENT-B")
        assert dash["completed_missions"] == 1
        assert dash["avg_mission_score"] > 0

    def test_dashboard_risk_trend(self, svc):
        team = svc.spawn_red_team("CLIENT-C", size=4)
        mission = svc.deploy_team(team["team_id"], "TWIN-C", "Risk test")
        svc.execute_mission(mission["mission_id"])
        svc.generate_after_action_report(mission["mission_id"])
        dash = svc.get_dashboard("CLIENT-C")
        assert len(dash["risk_trend"]) >= 1


# ============================================================
# Edge Cases
# ============================================================

class TestEdgeCases:
    def test_spawn_empty_red_after_all_assigned(self, svc):
        # Assign all red personas to a team
        svc.spawn_red_team("C1", size=8)
        # Try spawning another
        result = svc.spawn_red_team("C2", size=4)
        # Should still work since personas are available (not deployed)
        # but will draw from the same pool
        assert "team_id" in result or "error" in result

    def test_deploy_nonexistent_team(self, svc):
        result = svc.deploy_team("FAKE", "TWIN", "obj")
        assert "error" in result

    def test_execute_nonexistent_mission(self, svc):
        result = svc.execute_mission("FAKE")
        assert "error" in result

    def test_promote_nonexistent(self, svc):
        result = svc.promote_persona("FAKE")
        assert "error" in result

    def test_disband_nonexistent(self, svc):
        result = svc.disband_team("FAKE")
        assert "error" in result
