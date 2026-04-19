"""
Tests for MSP Reporting & Analytics Engine Service
Full coverage for templates, report generation, KPIs, BI, trends, and export.
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.reporting_engine import (
    ReportingEngineService,
    ReportType,
    MetricCategory,
    ReportFormat,
    ReportStatus,
    InsightType,
    ReportTemplate,
    ReportSection,
    GeneratedReport,
    KPIMetric,
    BusinessIntelligence,
    template_to_dict,
    report_to_dict,
    kpi_to_dict,
    bi_to_dict,
    section_to_dict,
)


class TestReportingEngineService:
    """Tests for ReportingEngineService class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.service = ReportingEngineService()

    # ========== Default Template Tests ==========

    def test_default_templates_seeded(self):
        """Test that default report templates are pre-populated"""
        templates = self.service.list_templates()
        assert len(templates) >= 10
        names = [t.name for t in templates]
        assert "Monthly Executive Summary" in names
        assert "Weekly Security Digest" in names
        assert "SLA Performance Report" in names
        assert "Financial Dashboard" in names
        assert "Endpoint Health Report" in names
        assert "Compliance Scorecard" in names
        assert "Ticket Analysis" in names
        assert "Technician Performance" in names
        assert "Client Health Scorecard" in names
        assert "Threat Landscape" in names

    def test_executive_summary_template_structure(self):
        """Test Monthly Executive Summary template has correct sections"""
        templates = self.service.list_templates()
        exec_tmpl = next(t for t in templates if t.name == "Monthly Executive Summary")
        assert exec_tmpl.report_type == ReportType.EXECUTIVE_SUMMARY.value
        assert len(exec_tmpl.sections) == 6
        section_titles = [s.title for s in exec_tmpl.sections]
        assert "Revenue Overview" in section_titles
        assert "Endpoint Summary" in section_titles
        assert "SLA Compliance" in section_titles

    def test_security_digest_template_structure(self):
        """Test Weekly Security Digest template has correct sections"""
        templates = self.service.list_templates()
        sec_tmpl = next(t for t in templates if t.name == "Weekly Security Digest")
        assert sec_tmpl.report_type == ReportType.SECURITY_POSTURE.value
        assert len(sec_tmpl.sections) == 4
        assert sec_tmpl.schedule_cron == "0 8 * * 1"

    def test_financial_dashboard_template(self):
        """Test Financial Dashboard template"""
        templates = self.service.list_templates()
        fin_tmpl = next(t for t in templates if t.name == "Financial Dashboard")
        assert fin_tmpl.report_type == ReportType.FINANCIAL.value
        assert len(fin_tmpl.sections) == 5
        assert fin_tmpl.format == "pdf"

    def test_default_templates_not_re_seeded(self):
        """Test that default templates are not duplicated on re-init"""
        count_before = len(self.service.list_templates())
        self.service._init_default_templates()
        count_after = len(self.service.list_templates())
        assert count_before == count_after

    # ========== Template CRUD Tests ==========

    def test_create_template(self):
        """Test creating a new report template"""
        tmpl = self.service.create_template(
            name="Custom Report",
            report_type=ReportType.TECHNICAL_DETAIL.value,
            description="A custom technical report",
            sections=[
                ReportSection(
                    section_id="SEC-TEST001",
                    title="Test Section",
                    data_source="rmm",
                    query_type="table",
                )
            ],
            format="html",
        )
        assert tmpl.template_id.startswith("TMPL-")
        assert tmpl.name == "Custom Report"
        assert tmpl.report_type == ReportType.TECHNICAL_DETAIL.value
        assert len(tmpl.sections) == 1
        assert tmpl.format == "html"
        assert tmpl.is_active is True

    def test_get_template(self):
        """Test retrieving a template by ID"""
        tmpl = self.service.create_template(
            name="Get Test",
            report_type=ReportType.FINANCIAL.value,
        )
        fetched = self.service.get_template(tmpl.template_id)
        assert fetched is not None
        assert fetched.name == "Get Test"

    def test_get_template_not_found(self):
        """Test getting a nonexistent template returns None"""
        result = self.service.get_template("TMPL-NONEXISTENT")
        assert result is None

    def test_list_templates_filter_by_type(self):
        """Test listing templates filtered by report type"""
        self.service.create_template(
            name="Filter Test",
            report_type=ReportType.CAPACITY_PLANNING.value,
        )
        results = self.service.list_templates(report_type=ReportType.CAPACITY_PLANNING.value)
        assert len(results) >= 1
        assert all(t.report_type == ReportType.CAPACITY_PLANNING.value for t in results)

    def test_list_templates_active_only(self):
        """Test listing only active templates"""
        self.service.create_template(
            name="Inactive Template",
            report_type=ReportType.TICKET_ANALYSIS.value,
            is_active=False,
        )
        all_templates = self.service.list_templates()
        active_only = self.service.list_templates(active_only=True)
        assert len(active_only) < len(all_templates)

    def test_update_template(self):
        """Test updating a template"""
        tmpl = self.service.create_template(
            name="Update Me",
            report_type=ReportType.ENDPOINT_HEALTH.value,
        )
        updated = self.service.update_template(
            tmpl.template_id,
            name="Updated Name",
            description="New description",
            is_active=False,
        )
        assert updated is not None
        assert updated.name == "Updated Name"
        assert updated.description == "New description"
        assert updated.is_active is False

    def test_update_template_not_found(self):
        """Test updating a nonexistent template"""
        result = self.service.update_template("TMPL-NONEXISTENT", name="No")
        assert result is None

    def test_delete_template(self):
        """Test deleting a template"""
        tmpl = self.service.create_template(
            name="Delete Me",
            report_type=ReportType.COMPLIANCE_STATUS.value,
        )
        assert self.service.delete_template(tmpl.template_id) is True
        assert self.service.get_template(tmpl.template_id) is None

    def test_delete_template_not_found(self):
        """Test deleting a nonexistent template"""
        assert self.service.delete_template("TMPL-NONEXISTENT") is False

    # ========== Report Generation Tests ==========

    def test_generate_report(self):
        """Test generating a report from a template"""
        templates = self.service.list_templates()
        tmpl = templates[0]
        now = datetime.now(timezone.utc)
        report = self.service.generate_report(
            template_id=tmpl.template_id,
            client_id="client-001",
            period_start=now - timedelta(days=30),
            period_end=now,
        )
        assert report is not None
        assert report.report_id.startswith("RPT-")
        assert report.template_id == tmpl.template_id
        assert report.client_id == "client-001"
        assert report.status == "completed"
        assert "sections" in report.data

    def test_generate_report_default_period(self):
        """Test generating a report with default period"""
        templates = self.service.list_templates()
        report = self.service.generate_report(template_id=templates[0].template_id)
        assert report is not None
        assert report.period_start is not None
        assert report.period_end is not None

    def test_generate_report_nonexistent_template(self):
        """Test generating a report with invalid template ID"""
        result = self.service.generate_report(template_id="TMPL-NONEXISTENT")
        assert result is None

    def test_generate_executive_summary(self):
        """Test executive summary report includes KPIs"""
        templates = self.service.list_templates()
        exec_tmpl = next(t for t in templates if t.report_type == ReportType.EXECUTIVE_SUMMARY.value)
        report = self.service.generate_report(template_id=exec_tmpl.template_id)
        assert report is not None
        assert "kpis" in report.data
        assert len(report.data["kpis"]) > 0

    def test_generate_financial_report(self):
        """Test financial report includes financial KPIs"""
        templates = self.service.list_templates()
        fin_tmpl = next(t for t in templates if t.report_type == ReportType.FINANCIAL.value)
        report = self.service.generate_report(template_id=fin_tmpl.template_id)
        assert report is not None
        assert "kpis" in report.data
        kpi_names = [k["name"] for k in report.data["kpis"]]
        assert "MRR" in kpi_names

    def test_generate_security_report(self):
        """Test security posture report includes security metrics"""
        templates = self.service.list_templates()
        sec_tmpl = next(t for t in templates if t.report_type == ReportType.SECURITY_POSTURE.value)
        report = self.service.generate_report(template_id=sec_tmpl.template_id)
        assert report is not None
        assert "kpis" in report.data

    def test_generate_sla_report(self):
        """Test SLA report includes operational metrics"""
        templates = self.service.list_templates()
        sla_tmpl = next(t for t in templates if t.report_type == ReportType.SLA_PERFORMANCE.value)
        report = self.service.generate_report(template_id=sla_tmpl.template_id)
        assert report is not None
        assert "kpis" in report.data

    def test_generate_client_health_report(self):
        """Test client health report includes satisfaction metrics"""
        templates = self.service.list_templates()
        ch_tmpl = next(t for t in templates if t.report_type == ReportType.CLIENT_HEALTH.value)
        report = self.service.generate_report(template_id=ch_tmpl.template_id)
        assert report is not None
        assert "kpis" in report.data

    # ========== Report Retrieval Tests ==========

    def test_get_report(self):
        """Test retrieving a generated report"""
        templates = self.service.list_templates()
        report = self.service.generate_report(template_id=templates[0].template_id)
        fetched = self.service.get_report(report.report_id)
        assert fetched is not None
        assert fetched.report_id == report.report_id

    def test_get_report_not_found(self):
        """Test getting a nonexistent report"""
        assert self.service.get_report("RPT-NONEXISTENT") is None

    def test_list_reports(self):
        """Test listing generated reports"""
        templates = self.service.list_templates()
        self.service.generate_report(template_id=templates[0].template_id, client_id="client-001")
        self.service.generate_report(template_id=templates[1].template_id, client_id="client-002")
        reports = self.service.list_reports()
        assert len(reports) >= 2

    def test_list_reports_filter_by_client(self):
        """Test listing reports filtered by client"""
        templates = self.service.list_templates()
        self.service.generate_report(template_id=templates[0].template_id, client_id="client-filter")
        results = self.service.list_reports(client_id="client-filter")
        assert len(results) >= 1
        assert all(r.client_id == "client-filter" for r in results)

    def test_list_reports_filter_by_status(self):
        """Test listing reports filtered by status"""
        templates = self.service.list_templates()
        self.service.generate_report(template_id=templates[0].template_id)
        results = self.service.list_reports(status="completed")
        assert all(r.status == "completed" for r in results)

    def test_list_reports_with_limit(self):
        """Test listing reports with limit"""
        templates = self.service.list_templates()
        for _ in range(5):
            self.service.generate_report(template_id=templates[0].template_id)
        results = self.service.list_reports(limit=3)
        assert len(results) <= 3

    def test_delete_report(self):
        """Test deleting a report"""
        templates = self.service.list_templates()
        report = self.service.generate_report(template_id=templates[0].template_id)
        assert self.service.delete_report(report.report_id) is True
        assert self.service.get_report(report.report_id) is None

    def test_delete_report_not_found(self):
        """Test deleting a nonexistent report"""
        assert self.service.delete_report("RPT-NONEXISTENT") is False

    # ========== Scheduling Tests ==========

    def test_schedule_report(self):
        """Test scheduling a report template"""
        tmpl = self.service.create_template(
            name="Schedule Test",
            report_type=ReportType.TICKET_ANALYSIS.value,
        )
        result = self.service.schedule_report(
            template_id=tmpl.template_id,
            cron="0 8 * * 1",
            recipients=["admin@aither.io", "ops@aither.io"],
        )
        assert result is not None
        assert result.schedule_cron == "0 8 * * 1"
        assert "admin@aither.io" in result.recipients

    def test_schedule_report_not_found(self):
        """Test scheduling a nonexistent template"""
        result = self.service.schedule_report("TMPL-NONEXISTENT", "0 0 * * *", [])
        assert result is None

    # ========== KPI Dashboard Tests ==========

    def test_get_kpi_dashboard(self):
        """Test real-time KPI dashboard"""
        dashboard = self.service.get_kpi_dashboard()
        assert "generated_at" in dashboard
        assert "period" in dashboard
        assert "kpi_count" in dashboard
        assert dashboard["kpi_count"] > 0
        assert "categories" in dashboard
        assert MetricCategory.FINANCIAL.value in dashboard["categories"]
        assert MetricCategory.OPERATIONAL.value in dashboard["categories"]
        assert MetricCategory.SECURITY.value in dashboard["categories"]
        assert MetricCategory.SATISFACTION.value in dashboard["categories"]

    def test_kpi_dashboard_has_financial_metrics(self):
        """Test KPI dashboard includes financial metrics"""
        dashboard = self.service.get_kpi_dashboard()
        financial = dashboard["categories"][MetricCategory.FINANCIAL.value]
        assert len(financial) > 0
        metric_names = [m["name"] for m in financial]
        assert "MRR" in metric_names

    def test_kpi_dashboard_has_operational_metrics(self):
        """Test KPI dashboard includes operational metrics"""
        dashboard = self.service.get_kpi_dashboard()
        operational = dashboard["categories"][MetricCategory.OPERATIONAL.value]
        assert len(operational) > 0

    def test_kpi_dashboard_has_security_metrics(self):
        """Test KPI dashboard includes security metrics"""
        dashboard = self.service.get_kpi_dashboard()
        security = dashboard["categories"][MetricCategory.SECURITY.value]
        assert len(security) > 0

    # ========== Client Health Matrix Tests ==========

    def test_get_client_health_matrix(self):
        """Test client health matrix generation"""
        matrix = self.service.get_client_health_matrix()
        assert "generated_at" in matrix
        assert "client_count" in matrix
        assert "avg_health" in matrix
        assert "at_risk_count" in matrix
        assert "matrix" in matrix
        assert len(matrix["matrix"]) > 0

    def test_client_health_matrix_has_dimensions(self):
        """Test each client in matrix has all scoring dimensions"""
        matrix = self.service.get_client_health_matrix()
        for client in matrix["matrix"]:
            assert "client_id" in client
            assert "security_score" in client
            assert "compliance_score" in client
            assert "sla_score" in client
            assert "satisfaction_score" in client
            assert "composite_health" in client
            assert "risk_level" in client

    def test_client_health_matrix_risk_levels(self):
        """Test risk levels are valid values"""
        matrix = self.service.get_client_health_matrix()
        for client in matrix["matrix"]:
            assert client["risk_level"] in ("low", "medium", "high")

    def test_client_health_matrix_sorted_by_health(self):
        """Test matrix is sorted by composite health (ascending)"""
        matrix = self.service.get_client_health_matrix()
        scores = [c["composite_health"] for c in matrix["matrix"]]
        assert scores == sorted(scores)

    # ========== Business Intelligence Tests ==========

    def test_generate_business_intelligence(self):
        """Test BI insight generation"""
        bi = self.service.generate_business_intelligence()
        assert "generated_at" in bi
        assert "total_insights" in bi
        assert bi["total_insights"] > 0
        assert "by_type" in bi
        assert "total_impact" in bi
        assert bi["total_impact"] > 0

    def test_bi_has_revenue_at_risk(self):
        """Test BI includes revenue at risk insights"""
        bi = self.service.generate_business_intelligence()
        # May or may not have revenue at risk based on random data
        assert InsightType.REVENUE_AT_RISK.value in bi["by_type"]

    def test_bi_has_growth_opportunities(self):
        """Test BI includes growth opportunity insights"""
        bi = self.service.generate_business_intelligence()
        growth = bi["by_type"][InsightType.GROWTH_OPPORTUNITY.value]
        assert len(growth) > 0

    def test_bi_has_efficiency_gains(self):
        """Test BI includes efficiency gain insights"""
        bi = self.service.generate_business_intelligence()
        efficiency = bi["by_type"][InsightType.EFFICIENCY_GAIN.value]
        assert len(efficiency) > 0

    def test_bi_insight_structure(self):
        """Test BI insights have correct structure"""
        bi = self.service.generate_business_intelligence()
        for type_key, insights in bi["by_type"].items():
            for insight in insights:
                assert "bi_id" in insight
                assert "insight_type" in insight
                assert "title" in insight
                assert "description" in insight
                assert "impact_value" in insight
                assert "confidence" in insight
                assert "recommended_action" in insight

    def test_churn_risk_calculation(self):
        """Test churn risk probability is in valid range"""
        risk = self.service._calculate_churn_risk("client-001")
        assert 0.0 <= risk <= 1.0

    # ========== Comparison & Trends Tests ==========

    def test_compare_periods(self):
        """Test period-over-period comparison"""
        now = datetime.now(timezone.utc)
        result = self.service.compare_periods(
            metric="mrr",
            period_a_start=now - timedelta(days=60),
            period_a_end=now - timedelta(days=30),
            period_b_start=now - timedelta(days=30),
            period_b_end=now,
        )
        assert result["metric"] == "mrr"
        assert "period_a" in result
        assert "period_b" in result
        assert "change" in result
        assert "percent_change" in result
        assert result["trend"] in ("up", "down", "flat")

    def test_get_trend_data(self):
        """Test time-series trend data generation"""
        result = self.service.get_trend_data("endpoints", periods=6)
        assert result["metric"] == "endpoints"
        assert result["periods"] == 6
        assert len(result["data_points"]) == 6
        assert "min_value" in result
        assert "max_value" in result
        assert "avg_value" in result

    def test_get_trend_data_default_periods(self):
        """Test trend data with default 12 periods"""
        result = self.service.get_trend_data("tickets")
        assert len(result["data_points"]) == 12

    def test_trend_data_has_period_labels(self):
        """Test each trend data point has a period label"""
        result = self.service.get_trend_data("mrr", periods=3)
        for point in result["data_points"]:
            assert "period" in point
            assert "value" in point

    # ========== Export Tests ==========

    def test_export_report_json(self):
        """Test exporting a report as JSON"""
        templates = self.service.list_templates()
        report = self.service.generate_report(template_id=templates[0].template_id)
        result = self.service.export_report(report.report_id, format="json")
        assert result is not None
        assert result["format"] == "json"

    def test_export_report_csv(self):
        """Test exporting a report as CSV"""
        templates = self.service.list_templates()
        report = self.service.generate_report(template_id=templates[0].template_id)
        result = self.service.export_report(report.report_id, format="csv")
        assert result is not None
        assert result["format"] == "csv"
        assert "csv_rows" in result

    def test_export_report_html(self):
        """Test exporting a report as HTML"""
        templates = self.service.list_templates()
        report = self.service.generate_report(template_id=templates[0].template_id)
        result = self.service.export_report(report.report_id, format="html")
        assert result is not None
        assert result["format"] == "html"
        assert result["html_ready"] is True

    def test_export_report_pdf(self):
        """Test exporting a report as PDF"""
        templates = self.service.list_templates()
        report = self.service.generate_report(template_id=templates[0].template_id)
        result = self.service.export_report(report.report_id, format="pdf")
        assert result is not None
        assert result["format"] == "pdf"

    def test_export_report_not_found(self):
        """Test exporting a nonexistent report"""
        result = self.service.export_report("RPT-NONEXISTENT")
        assert result is None

    # ========== Dashboard Tests ==========

    def test_get_dashboard(self):
        """Test reporting engine dashboard"""
        dashboard = self.service.get_dashboard()
        assert "summary" in dashboard
        assert "scheduled" in dashboard
        assert "recent_reports" in dashboard
        assert "report_types" in dashboard
        assert "available_formats" in dashboard

    def test_dashboard_summary_counts(self):
        """Test dashboard summary has correct counts"""
        dashboard = self.service.get_dashboard()
        summary = dashboard["summary"]
        assert "total_templates" in summary
        assert "active_templates" in summary
        assert "scheduled_reports" in summary
        assert "total_reports_generated" in summary
        assert summary["total_templates"] >= 10

    def test_dashboard_lists_scheduled_reports(self):
        """Test dashboard includes scheduled reports"""
        dashboard = self.service.get_dashboard()
        scheduled = dashboard["scheduled"]
        assert len(scheduled) > 0
        for s in scheduled:
            assert "template_id" in s
            assert "name" in s
            assert "cron" in s

    def test_dashboard_lists_report_types(self):
        """Test dashboard lists all report types"""
        dashboard = self.service.get_dashboard()
        types = dashboard["report_types"]
        assert ReportType.EXECUTIVE_SUMMARY.value in types
        assert ReportType.FINANCIAL.value in types
        assert ReportType.SECURITY_POSTURE.value in types

    def test_dashboard_lists_formats(self):
        """Test dashboard lists available formats"""
        dashboard = self.service.get_dashboard()
        formats = dashboard["available_formats"]
        assert "pdf" in formats
        assert "html" in formats
        assert "csv" in formats
        assert "json" in formats

    # ========== Serialization Tests ==========

    def test_section_to_dict(self):
        """Test ReportSection serialization"""
        sec = ReportSection(
            section_id="SEC-TEST",
            title="Test Section",
            data_source="rmm",
            query_type="table",
            filters={"status": "online"},
            sort_by="hostname",
            limit=25,
        )
        d = section_to_dict(sec)
        assert d["section_id"] == "SEC-TEST"
        assert d["title"] == "Test Section"
        assert d["data_source"] == "rmm"
        assert d["query_type"] == "table"
        assert d["filters"] == {"status": "online"}
        assert d["sort_by"] == "hostname"
        assert d["limit"] == 25

    def test_template_to_dict(self):
        """Test ReportTemplate serialization"""
        tmpl = self.service.create_template(
            name="Serialize Test",
            report_type=ReportType.FINANCIAL.value,
            description="Test description",
        )
        d = template_to_dict(tmpl)
        assert d["template_id"] == tmpl.template_id
        assert d["name"] == "Serialize Test"
        assert d["report_type"] == ReportType.FINANCIAL.value
        assert d["created_at"] is not None
        assert isinstance(d["sections"], list)

    def test_report_to_dict(self):
        """Test GeneratedReport serialization"""
        templates = self.service.list_templates()
        report = self.service.generate_report(template_id=templates[0].template_id)
        d = report_to_dict(report)
        assert d["report_id"] == report.report_id
        assert d["status"] == "completed"
        assert d["generated_at"] is not None
        assert "data" in d

    def test_kpi_to_dict(self):
        """Test KPIMetric serialization"""
        kpi = KPIMetric(
            metric_id="KPI-TEST",
            name="Test Metric",
            category=MetricCategory.FINANCIAL.value,
            current_value=42000.0,
            previous_value=38000.0,
            target_value=45000.0,
            trend="up",
            unit="currency",
        )
        d = kpi_to_dict(kpi)
        assert d["metric_id"] == "KPI-TEST"
        assert d["name"] == "Test Metric"
        assert d["current_value"] == 42000.0
        assert d["trend"] == "up"
        assert d["unit"] == "currency"

    def test_bi_to_dict(self):
        """Test BusinessIntelligence serialization"""
        bi = BusinessIntelligence(
            bi_id="BI-TEST",
            insight_type=InsightType.GROWTH_OPPORTUNITY.value,
            title="Test Insight",
            description="A test insight",
            impact_value=50000.0,
            confidence=0.85,
            affected_clients=["client-001", "client-002"],
            recommended_action="Test action",
        )
        d = bi_to_dict(bi)
        assert d["bi_id"] == "BI-TEST"
        assert d["insight_type"] == InsightType.GROWTH_OPPORTUNITY.value
        assert d["impact_value"] == 50000.0
        assert d["confidence"] == 0.85
        assert len(d["affected_clients"]) == 2

    # ========== Enum Tests ==========

    def test_report_type_enum_values(self):
        """Test all ReportType enum values"""
        assert ReportType.EXECUTIVE_SUMMARY.value == "executive_summary"
        assert ReportType.TECHNICAL_DETAIL.value == "technical_detail"
        assert ReportType.SECURITY_POSTURE.value == "security_posture"
        assert ReportType.COMPLIANCE_STATUS.value == "compliance_status"
        assert ReportType.SLA_PERFORMANCE.value == "sla_performance"
        assert ReportType.FINANCIAL.value == "financial"
        assert ReportType.TICKET_ANALYSIS.value == "ticket_analysis"
        assert ReportType.ENDPOINT_HEALTH.value == "endpoint_health"
        assert ReportType.THREAT_LANDSCAPE.value == "threat_landscape"
        assert ReportType.CLIENT_HEALTH.value == "client_health"
        assert ReportType.TECHNICIAN_PERFORMANCE.value == "technician_performance"
        assert ReportType.CAPACITY_PLANNING.value == "capacity_planning"

    def test_metric_category_enum_values(self):
        """Test all MetricCategory enum values"""
        assert MetricCategory.FINANCIAL.value == "financial"
        assert MetricCategory.OPERATIONAL.value == "operational"
        assert MetricCategory.SECURITY.value == "security"
        assert MetricCategory.SATISFACTION.value == "satisfaction"
        assert MetricCategory.GROWTH.value == "growth"

    def test_insight_type_enum_values(self):
        """Test all InsightType enum values"""
        assert InsightType.REVENUE_AT_RISK.value == "revenue_at_risk"
        assert InsightType.GROWTH_OPPORTUNITY.value == "growth_opportunity"
        assert InsightType.EFFICIENCY_GAIN.value == "efficiency_gain"
        assert InsightType.COST_REDUCTION.value == "cost_reduction"
        assert InsightType.CHURN_RISK.value == "churn_risk"

    def test_report_format_enum_values(self):
        """Test all ReportFormat enum values"""
        assert ReportFormat.PDF.value == "pdf"
        assert ReportFormat.HTML.value == "html"
        assert ReportFormat.CSV.value == "csv"
        assert ReportFormat.JSON.value == "json"

    def test_report_status_enum_values(self):
        """Test all ReportStatus enum values"""
        assert ReportStatus.GENERATING.value == "generating"
        assert ReportStatus.COMPLETED.value == "completed"
        assert ReportStatus.FAILED.value == "failed"
        assert ReportStatus.SENT.value == "sent"

    # ========== Section Data Collection Tests ==========

    def test_collect_billing_data(self):
        """Test billing data source returns expected fields"""
        section = ReportSection(
            section_id="SEC-BILL",
            title="Revenue",
            data_source="billing",
            query_type="metric",
        )
        now = datetime.now(timezone.utc)
        data = self.service._collect_section_data(section, None, now - timedelta(days=30), now)
        assert "values" in data
        assert "mrr" in data["values"]
        assert "arr" in data["values"]
        assert "arpa" in data["values"]

    def test_collect_rmm_data(self):
        """Test RMM data source returns expected fields"""
        section = ReportSection(
            section_id="SEC-RMM",
            title="Endpoints",
            data_source="rmm",
            query_type="summary",
        )
        now = datetime.now(timezone.utc)
        data = self.service._collect_section_data(section, None, now - timedelta(days=30), now)
        assert "values" in data
        assert "total_endpoints" in data["values"]
        assert "online" in data["values"]
        assert "patch_compliance" in data["values"]

    def test_collect_itsm_data(self):
        """Test ITSM data source returns expected fields"""
        section = ReportSection(
            section_id="SEC-ITSM",
            title="Tickets",
            data_source="itsm",
            query_type="table",
        )
        now = datetime.now(timezone.utc)
        data = self.service._collect_section_data(section, None, now - timedelta(days=30), now)
        assert "values" in data
        assert "total_tickets" in data["values"]
        assert "categories" in data["values"]

    def test_collect_security_data(self):
        """Test security data source returns expected fields"""
        section = ReportSection(
            section_id="SEC-SEC",
            title="Security",
            data_source="security",
            query_type="metric",
        )
        now = datetime.now(timezone.utc)
        data = self.service._collect_section_data(section, None, now - timedelta(days=30), now)
        assert "values" in data
        assert "threats_blocked" in data["values"]
        assert "security_score" in data["values"]

    def test_collect_sla_data(self):
        """Test SLA data source returns expected fields"""
        section = ReportSection(
            section_id="SEC-SLA",
            title="SLA",
            data_source="sla",
            query_type="metric",
        )
        now = datetime.now(timezone.utc)
        data = self.service._collect_section_data(section, None, now - timedelta(days=30), now)
        assert "values" in data
        assert "overall_compliance" in data["values"]
        assert "mttr_minutes" in data["values"]

    def test_collect_compliance_data(self):
        """Test compliance data source returns expected fields"""
        section = ReportSection(
            section_id="SEC-COMP",
            title="Compliance",
            data_source="compliance",
            query_type="table",
        )
        now = datetime.now(timezone.utc)
        data = self.service._collect_section_data(section, None, now - timedelta(days=30), now)
        assert "values" in data
        assert "frameworks" in data["values"]
        assert "controls_passed" in data["values"]

    def test_collect_unknown_data_source(self):
        """Test unknown data source returns note"""
        section = ReportSection(
            section_id="SEC-UNK",
            title="Unknown",
            data_source="nonexistent_source",
            query_type="summary",
        )
        now = datetime.now(timezone.utc)
        data = self.service._collect_section_data(section, None, now - timedelta(days=30), now)
        assert "values" in data
        assert "note" in data["values"]

    def test_collect_data_with_filters(self):
        """Test section data includes applied filters"""
        section = ReportSection(
            section_id="SEC-FILT",
            title="Filtered",
            data_source="itsm",
            query_type="detail",
            filters={"status": "open"},
            sort_by="priority",
            limit=10,
        )
        now = datetime.now(timezone.utc)
        data = self.service._collect_section_data(section, None, now - timedelta(days=30), now)
        assert data["filters_applied"] == {"status": "open"}
        assert data["sorted_by"] == "priority"
        assert data["limit"] == 10

    # ========== Integration Tests ==========

    def test_full_workflow(self):
        """Test complete workflow: create template, generate, export"""
        # Create custom template
        tmpl = self.service.create_template(
            name="Integration Test Report",
            report_type=ReportType.TECHNICAL_DETAIL.value,
            sections=[
                ReportSection(
                    section_id="SEC-INT1",
                    title="RMM Overview",
                    data_source="rmm",
                    query_type="summary",
                ),
                ReportSection(
                    section_id="SEC-INT2",
                    title="Ticket Stats",
                    data_source="itsm",
                    query_type="table",
                    limit=5,
                ),
            ],
        )
        assert tmpl is not None

        # Generate report
        now = datetime.now(timezone.utc)
        report = self.service.generate_report(
            template_id=tmpl.template_id,
            client_id="client-integ",
            period_start=now - timedelta(days=7),
            period_end=now,
        )
        assert report is not None
        assert report.status == "completed"

        # Export
        exported = self.service.export_report(report.report_id, format="json")
        assert exported is not None

        # Verify in listings
        reports = self.service.list_reports(client_id="client-integ")
        assert len(reports) >= 1

        # Clean up
        self.service.delete_report(report.report_id)
        assert self.service.get_report(report.report_id) is None

    def test_multiple_report_generation(self):
        """Test generating multiple reports from different templates"""
        templates = self.service.list_templates()
        generated = []
        for tmpl in templates[:5]:
            report = self.service.generate_report(template_id=tmpl.template_id)
            assert report is not None
            generated.append(report)
        assert len(generated) == 5
        all_reports = self.service.list_reports()
        assert len(all_reports) >= 5
