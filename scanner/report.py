"""
report.py

Professional Report Generator.

This module combines the structured RiskReport
and AI-generated SecurityAnalysis into a single
professional security assessment.

Responsibilities
----------------
1. Merge validated findings.
2. Merge AI explanations.
3. Generate executive reports.
4. Generate developer reports.
5. Export reports.
"""

from __future__ import annotations

import json
import logging
import time

from dataclasses import dataclass
from typing import Any, Dict, List

from scanner.risk_engine import (
    RiskReport,
)

from scanner.analyst import (
    SecurityAnalysis,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------
# Data Model
# ---------------------------------------------------------

@dataclass
class SecurityReport:
    """
    Final report produced by API Sentinel AI.
    """

    generated_at: float

    endpoint: str

    overall_score: float

    overall_rating: str

    executive_summary: str

    technical_analysis: str

    business_impact: str

    remediation: str

    secure_coding: str

    conclusion: str

    findings: List[Dict[str, Any]]


# ---------------------------------------------------------
# Exceptions
# ---------------------------------------------------------

class ReportGenerationError(Exception):
    """Raised when report generation fails."""


# ---------------------------------------------------------
# Report Generator
# ---------------------------------------------------------

class ReportGenerator:
    """
    Merge the outputs from the Risk Engine and
    AI Security Analyst into one professional
    report.
    """

    def __init__(self):

        logger.info(
            "Professional Report Generator initialized."
        )

    # -----------------------------------------------------
    # Public API
    # -----------------------------------------------------

    def generate(
        self,
        risk_report: RiskReport,
        analysis: SecurityAnalysis,
    ) -> SecurityReport:
        """
        Generate the final security report.
        """

        endpoint = (
            risk_report.validation_report
            .execution_report
            .plan
            .endpoint
            .endpoint
        )

        findings = []

        for finding in risk_report.findings:

            findings.append(
                {
                    "title": finding.finding.title,
                    "severity": finding.finding.severity,
                    "priority": finding.priority,
                    "score": finding.score,
                    "recommendation":
                        finding.finding.recommendation,
                }
            )

        return SecurityReport(
            generated_at=time.time(),
            endpoint=f"{endpoint.method} {endpoint.path}",
            overall_score=risk_report.overall_score,
            overall_rating=risk_report.overall_rating,
            executive_summary=analysis.executive_summary,
            technical_analysis=analysis.technical_summary,
            business_impact=analysis.business_impact,
            remediation=analysis.remediation_plan,
            secure_coding=analysis.secure_coding_advice,
            conclusion=analysis.conclusion,
            findings=findings,
        )
    # ---------------------------------------------------------
    # Report Sections
    # ---------------------------------------------------------

    def _endpoint_information(
        self,
        report: SecurityReport,
    ) -> Dict[str, Any]:
        """
        Generate endpoint information.
        """

        return {
            "endpoint": report.endpoint,
            "generated_at": report.generated_at,
            "overall_score": report.overall_score,
            "overall_rating": report.overall_rating,
        }

    # ---------------------------------------------------------
    # Executive Section
    # ---------------------------------------------------------

    def _executive_section(
        self,
        report: SecurityReport,
    ) -> Dict[str, Any]:
        """
        Generate the executive summary section.
        """

        return {
            "summary": report.executive_summary,
            "business_impact": report.business_impact,
            "overall_rating": report.overall_rating,
            "overall_score": report.overall_score,
        }

    # ---------------------------------------------------------
    # Technical Section
    # ---------------------------------------------------------

    def _technical_section(
        self,
        report: SecurityReport,
    ) -> Dict[str, Any]:
        """
        Generate the technical analysis section.
        """

        return {
            "analysis": report.technical_analysis,
            "findings": report.findings,
        }

    # ---------------------------------------------------------
    # Remediation Section
    # ---------------------------------------------------------

    def _remediation_section(
        self,
        report: SecurityReport,
    ) -> Dict[str, Any]:
        """
        Generate remediation details.
        """

        return {
            "remediation": report.remediation,
            "secure_coding": report.secure_coding,
        }

    # ---------------------------------------------------------
    # Conclusion Section
    # ---------------------------------------------------------

    def _conclusion_section(
        self,
        report: SecurityReport,
    ) -> Dict[str, Any]:
        """
        Generate conclusion section.
        """

        return {
            "conclusion": report.conclusion,
        }

    # ---------------------------------------------------------
    # Complete Report
    # ---------------------------------------------------------

    def build_report(
        self,
        report: SecurityReport,
    ) -> Dict[str, Any]:
        """
        Build the complete structured report.
        """

        return {

            "endpoint_information":
                self._endpoint_information(
                    report
                ),

            "executive_summary":
                self._executive_section(
                    report
                ),

            "technical_analysis":
                self._technical_section(
                    report
                ),

            "remediation":
                self._remediation_section(
                    report
                ),

            "conclusion":
                self._conclusion_section(
                    report
                ),
        }
    # ---------------------------------------------------------
    # Executive Metrics
    # ---------------------------------------------------------

    def executive_metrics(
        self,
        risk_report: RiskReport,
    ) -> Dict[str, Any]:
        """
        Generate executive-level security metrics.
        """

        findings = risk_report.findings

        severity_breakdown = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }

        priority_breakdown = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }

        owasp_breakdown: Dict[str, int] = {}

        for finding in findings:

            severity = (
                finding.finding.severity.upper()
            )

            priority = (
                finding.priority.upper()
            )

            category = (
                finding.finding.owasp_category
            )

            severity_breakdown.setdefault(
                severity,
                0,
            )

            severity_breakdown[severity] += 1

            priority_breakdown.setdefault(
                priority,
                0,
            )

            priority_breakdown[priority] += 1

            owasp_breakdown.setdefault(
                category,
                0,
            )

            owasp_breakdown[category] += 1

        return {
            "overall_score": (
                risk_report.overall_score
            ),
            "overall_rating": (
                risk_report.overall_rating
            ),
            "total_findings": len(findings),
            "severity_breakdown": severity_breakdown,
            "priority_breakdown": priority_breakdown,
            "owasp_breakdown": owasp_breakdown,
        }

    # ---------------------------------------------------------
    # Prioritized Findings
    # ---------------------------------------------------------

    def prioritized_findings(
        self,
        risk_report: RiskReport,
    ) -> List[Dict[str, Any]]:
        """
        Return findings ordered by risk score.
        """

        ordered = sorted(
            risk_report.findings,
            key=lambda finding: finding.score,
            reverse=True,
        )

        return [

            {
                "title":
                    finding.finding.title,

                "severity":
                    finding.finding.severity,

                "priority":
                    finding.priority,

                "score":
                    finding.score,

                "owasp_category":
                    finding.finding.owasp_category,

                "recommendation":
                    finding.finding.recommendation,
            }

            for finding in ordered

        ]

    # ---------------------------------------------------------
    # Risk Overview
    # ---------------------------------------------------------

    def risk_overview(
        self,
        risk_report: RiskReport,
    ) -> Dict[str, Any]:
        """
        Generate a concise risk overview.
        """

        top_finding = None

        if risk_report.findings:

            highest = max(
                risk_report.findings,
                key=lambda finding: finding.score,
            )

            top_finding = {
                "title":
                    highest.finding.title,

                "score":
                    highest.score,

                "severity":
                    highest.finding.severity,

                "priority":
                    highest.priority,
            }

        return {
            "overall_score":
                risk_report.overall_score,

            "overall_rating":
                risk_report.overall_rating,

            "highest_risk":
                top_finding,

            "total_findings":
                len(risk_report.findings),
        }

    # ---------------------------------------------------------
    # Dashboard Payload
    # ---------------------------------------------------------

    def dashboard_payload(
        self,
        report: SecurityReport,
        risk_report: RiskReport,
    ) -> Dict[str, Any]:
        """
        Generate a lightweight payload
        for the dashboard.
        """

        return {

            "endpoint":
                report.endpoint,

            "overall_score":
                report.overall_score,

            "overall_rating":
                report.overall_rating,

            "executive_summary":
                report.executive_summary,

            "metrics":
                self.executive_metrics(
                    risk_report
                ),

            "top_findings":
                self.prioritized_findings(
                    risk_report
                )[:5],
        }
    # ---------------------------------------------------------
    # Serialization
    # ---------------------------------------------------------

    def report_to_dict(
        self,
        report: SecurityReport,
    ) -> Dict[str, Any]:
        """
        Convert a SecurityReport into a
        serializable dictionary.
        """

        return {

            "generated_at": report.generated_at,

            "endpoint": report.endpoint,

            "overall_score": report.overall_score,

            "overall_rating": report.overall_rating,

            "executive_summary":
                report.executive_summary,

            "technical_analysis":
                report.technical_analysis,

            "business_impact":
                report.business_impact,

            "remediation":
                report.remediation,

            "secure_coding":
                report.secure_coding,

            "conclusion":
                report.conclusion,

            "findings":
                report.findings,
        }

    # ---------------------------------------------------------
    # Markdown Report
    # ---------------------------------------------------------

    def generate_markdown(
        self,
        report: SecurityReport,
    ) -> str:
        """
        Generate a professional Markdown report.
        """

        lines = [

            "# API Sentinel AI Security Report",

            "",

            "## Endpoint",

            report.endpoint,

            "",

            f"**Overall Score:** {report.overall_score}",

            f"**Overall Rating:** {report.overall_rating}",

            "",

            "---",

            "",

            "## Executive Summary",

            report.executive_summary,

            "",

            "## Technical Analysis",

            report.technical_analysis,

            "",

            "## Business Impact",

            report.business_impact,

            "",

            "## Recommended Remediation",

            report.remediation,

            "",

            "## Secure Coding Advice",

            report.secure_coding,

            "",

            "## Findings",

            "",
        ]

        for index, finding in enumerate(
            report.findings,
            start=1,
        ):

            lines.extend(
                [

                    f"### {index}. {finding['title']}",

                    f"- Severity: {finding['severity']}",

                    f"- Priority: {finding['priority']}",

                    f"- Risk Score: {finding['score']}",

                    f"- Recommendation: {finding['recommendation']}",

                    "",
                ]
            )

        lines.extend(
            [

                "## Conclusion",

                report.conclusion,

            ]
        )

        return "\n".join(lines)

    # ---------------------------------------------------------
    # Dashboard Export
    # ---------------------------------------------------------

    def dashboard_data(
        self,
        report: SecurityReport,
    ) -> Dict[str, Any]:
        """
        Create a lightweight payload
        for the web dashboard.
        """

        return {

            "endpoint":
                report.endpoint,

            "overall_score":
                report.overall_score,

            "overall_rating":
                report.overall_rating,

            "total_findings":
                len(report.findings),

            "findings":
                report.findings,

            "executive_summary":
                report.executive_summary,
        }

    # ---------------------------------------------------------
    # Statistics
    # ---------------------------------------------------------

    def statistics(
        self,
        report: SecurityReport,
    ) -> Dict[str, Any]:
        """
        Generate report statistics.
        """

        severity = {}

        priority = {}

        for finding in report.findings:

            sev = finding["severity"]

            pri = finding["priority"]

            severity[sev] = (
                severity.get(sev, 0) + 1
            )

            priority[pri] = (
                priority.get(pri, 0) + 1
            )

        return {

            "overall_score":
                report.overall_score,

            "overall_rating":
                report.overall_rating,

            "total_findings":
                len(report.findings),

            "severity_breakdown":
                severity,

            "priority_breakdown":
                priority,
        }
    # ---------------------------------------------------------
    # Export
    # ---------------------------------------------------------

    def export_json(
        self,
        report: SecurityReport,
        output_file: str,
    ) -> None:
        """
        Export the report as JSON.
        """

        logger.info(
            "Exporting report to %s",
            output_file,
        )

        with open(
            output_file,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                self.report_to_dict(
                    report
                ),
                file,
                indent=4,
            )

    def export_markdown(
        self,
        report: SecurityReport,
        output_file: str,
    ) -> None:
        """
        Export the report as Markdown.
        """

        logger.info(
            "Exporting Markdown report."
        )

        with open(
            output_file,
            "w",
            encoding="utf-8",
        ) as file:

            file.write(
                self.generate_markdown(
                    report
                )
            )

    # ---------------------------------------------------------
    # Batch Report Generation
    # ---------------------------------------------------------

    def generate_reports(
        self,
        risk_reports: List[RiskReport],
        analyses: List[SecurityAnalysis],
    ) -> List[SecurityReport]:
        """
        Generate reports for multiple endpoints.
        """

        if len(risk_reports) != len(analyses):

            raise ReportGenerationError(
                "Risk report count and analysis count must match."
            )

        reports: List[
            SecurityReport
        ] = []

        logger.info(
            "Generating %d reports.",
            len(risk_reports),
        )

        for risk_report, analysis in zip(
            risk_reports,
            analyses,
        ):

            reports.append(
                self.generate(
                    risk_report,
                    analysis,
                )
            )

        logger.info(
            "Batch report generation complete."
        )

        return reports

    # ---------------------------------------------------------
    # Batch Export
    # ---------------------------------------------------------

    def export_report_collection(
        self,
        reports: List[SecurityReport],
        output_file: str,
    ) -> None:
        """
        Export multiple reports into one JSON file.
        """

        payload = [

            self.report_to_dict(
                report
            )

            for report in reports

        ]

        logger.info(
            "Exporting %d reports.",
            len(reports),
        )

        with open(
            output_file,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                payload,
                file,
                indent=4,
            )

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------

    def generate_summary(
        self,
        report: SecurityReport,
    ) -> Dict[str, Any]:
        """
        Generate a concise summary suitable for
        dashboards or CLI output.
        """

        highest = None

        if report.findings:

            highest = max(
                report.findings,
                key=lambda finding: finding["score"],
            )

        return {

            "endpoint":
                report.endpoint,

            "overall_score":
                report.overall_score,

            "overall_rating":
                report.overall_rating,

            "total_findings":
                len(report.findings),

            "highest_risk":
                highest,

            "generated_at":
                report.generated_at,
        }