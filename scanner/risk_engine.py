"""
risk_engine.py

Risk Scoring Engine for API Sentinel AI.

This module converts validated security findings into
prioritized business risks.

Responsibilities
----------------
1. Score validated findings.
2. Prioritize vulnerabilities.
3. Calculate endpoint risk.
4. Produce overall API risk score.

This module never discovers vulnerabilities.
It only scores existing findings.
"""

from __future__ import annotations

import json
import logging
import time

from dataclasses import dataclass, field
from typing import Any, Dict, List

from scanner.validator import (
    ValidationFinding,
    ValidationReport,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------
# Data Models
# ---------------------------------------------------------

@dataclass
class RiskFinding:
    """
    Represents a scored security finding.
    """

    finding: ValidationFinding

    score: float

    priority: str

    rationale: str


@dataclass
class RiskReport:
    """
    Represents the risk assessment for one endpoint.
    """

    validation_report: ValidationReport

    assessed_at: float

    overall_score: float = 0.0

    overall_rating: str = "LOW"

    findings: List[RiskFinding] = field(
        default_factory=list
    )


# ---------------------------------------------------------
# Exceptions
# ---------------------------------------------------------

class RiskEngineError(Exception):
    """Base Risk Engine exception."""


# ---------------------------------------------------------
# Risk Scoring Engine
# ---------------------------------------------------------

class RiskScoringEngine:
    """
    Calculate business risk from validated findings.
    """

    def score_report(
        self,
        report: ValidationReport,
    ) -> RiskReport:
        """
        Score every validated finding in a report.
        """

        logger.info(
            "Scoring validation report."
        )

        risk_report = RiskReport(
            validation_report=report,
            assessed_at=time.time(),
        )

        for result in report.results:

            for finding in result.findings:

                risk_report.findings.append(
                    self._score_finding(
                        finding
                    )
                )

        self._calculate_overall_score(
            risk_report
        )

        return risk_report

    # -----------------------------------------------------
    # Internal Methods
    # -----------------------------------------------------

    def _score_finding(
        self,
        finding: ValidationFinding,
    ) -> RiskFinding:
        raise NotImplementedError

    def _calculate_overall_score(
        self,
        report: RiskReport,
    ) -> None:
        raise NotImplementedError
    # ---------------------------------------------------------
    # Score Individual Finding
    # ---------------------------------------------------------

    def _score_finding(
        self,
        finding: ValidationFinding,
    ) -> RiskFinding:
        """
        Calculate the risk score for a validated finding.
        """

        severity_score = self._severity_score(
            finding.severity
        )

        confidence_score = (
            finding.confidence * 20
        )

        business_score = self._business_score(
            finding.owasp_category
        )

        total_score = min(
            severity_score
            + confidence_score
            + business_score,
            100,
        )

        return RiskFinding(
            finding=finding,
            score=round(total_score, 2),
            priority=self._priority_level(
                total_score
            ),
            rationale=(
                "Calculated using severity, "
                "confidence, and business impact."
            ),
        )

    # ---------------------------------------------------------
    # Severity Weight
    # ---------------------------------------------------------

    def _severity_score(
        self,
        severity: str,
    ) -> float:
        """
        Convert severity into a numerical score.
        """

        mapping = {
            "LOW": 20,
            "MEDIUM": 40,
            "HIGH": 60,
            "CRITICAL": 80,
        }

        return mapping.get(
            severity.upper(),
            20,
        )

    # ---------------------------------------------------------
    # Business Impact
    # ---------------------------------------------------------

    def _business_score(
        self,
        category: str,
    ) -> float:
        """
        Assign business impact based on OWASP category.
        """

        critical_categories = {
            "API1",
            "API2",
            "API3",
        }

        medium_categories = {
            "API4",
            "API5",
            "API6",
        }

        if category in critical_categories:
            return 15

        if category in medium_categories:
            return 10

        return 5

    # ---------------------------------------------------------
    # Priority Level
    # ---------------------------------------------------------

    def _priority_level(
        self,
        score: float,
    ) -> str:
        """
        Convert score into a priority.
        """

        if score >= 90:
            return "CRITICAL"

        if score >= 75:
            return "HIGH"

        if score >= 50:
            return "MEDIUM"

        return "LOW"

    # ---------------------------------------------------------
    # Overall Risk Calculation
    # ---------------------------------------------------------

    def _calculate_overall_score(
        self,
        report: RiskReport,
    ) -> None:
        """
        Calculate the overall endpoint risk score.
        """

        if not report.findings:

            report.overall_score = 0
            report.overall_rating = "LOW"

            return

        average = (
            sum(
                finding.score
                for finding in report.findings
            )
            / len(report.findings)
        )

        report.overall_score = round(
            average,
            2,
        )

        report.overall_rating = self._priority_level(
            average
        )
    # ---------------------------------------------------------
    # Highest Risk Findings
    # ---------------------------------------------------------

    def highest_risk_findings(
        self,
        report: RiskReport,
        limit: int = 5,
    ) -> List[RiskFinding]:
        """
        Return the highest-risk findings.
        """

        return sorted(
            report.findings,
            key=lambda finding: finding.score,
            reverse=True,
        )[:limit]

    # ---------------------------------------------------------
    # OWASP Breakdown
    # ---------------------------------------------------------

    def owasp_breakdown(
        self,
        report: RiskReport,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Generate statistics grouped by OWASP category.
        """

        breakdown: Dict[str, Dict[str, Any]] = {}

        for finding in report.findings:

            category = finding.finding.owasp_category

            if category not in breakdown:

                breakdown[category] = {
                    "count": 0,
                    "average_score": 0.0,
                    "highest_score": 0.0,
                }

            breakdown[category]["count"] += 1

            breakdown[category]["average_score"] += finding.score

            breakdown[category]["highest_score"] = max(
                breakdown[category]["highest_score"],
                finding.score,
            )

        for category, values in breakdown.items():

            values["average_score"] = round(
                values["average_score"] / values["count"],
                2,
            )

        return breakdown

    # ---------------------------------------------------------
    # Priority Breakdown
    # ---------------------------------------------------------

    def priority_breakdown(
        self,
        report: RiskReport,
    ) -> Dict[str, int]:
        """
        Count findings by priority.
        """

        priorities = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }

        for finding in report.findings:

            priority = finding.priority.upper()

            if priority in priorities:

                priorities[priority] += 1

        return priorities

    # ---------------------------------------------------------
    # Endpoint Summary
    # ---------------------------------------------------------

    def endpoint_summary(
        self,
        report: RiskReport,
    ) -> Dict[str, Any]:
        """
        Generate a concise endpoint-level summary.
        """

        endpoint = (
            report.validation_report
            .execution_report
            .plan
            .endpoint
            .endpoint
        )

        highest = self.highest_risk_findings(
            report,
            limit=1,
        )

        return {
            "endpoint": (
                f"{endpoint.method} {endpoint.path}"
            ),
            "overall_score": report.overall_score,
            "overall_rating": report.overall_rating,
            "total_findings": len(report.findings),
            "highest_risk": (
                highest[0].finding.title
                if highest
                else None
            ),
            "priority_breakdown": self.priority_breakdown(
                report
            ),
        }

    # ---------------------------------------------------------
    # API Metrics
    # ---------------------------------------------------------

    def risk_metrics(
        self,
        report: RiskReport,
    ) -> Dict[str, Any]:
        """
        Generate metrics used by dashboards and reports.
        """

        return {
            "overall_score": report.overall_score,
            "overall_rating": report.overall_rating,
            "total_findings": len(report.findings),
            "highest_score": (
                max(
                    finding.score
                    for finding in report.findings
                )
                if report.findings
                else 0
            ),
            "average_score": (
                round(
                    sum(
                        finding.score
                        for finding in report.findings
                    )
                    / len(report.findings),
                    2,
                )
                if report.findings
                else 0
            ),
            "owasp_breakdown": self.owasp_breakdown(
                report
            ),
        }
    # ---------------------------------------------------------
    # Prioritize Findings
    # ---------------------------------------------------------

    def prioritize_findings(
        self,
        report: RiskReport,
    ) -> List[RiskFinding]:
        """
        Return findings sorted by descending risk score.
        """

        return sorted(
            report.findings,
            key=lambda finding: (
                finding.score,
                finding.finding.confidence,
            ),
            reverse=True,
        )

    # ---------------------------------------------------------
    # Remediation Recommendations
    # ---------------------------------------------------------

    def remediation_plan(
        self,
        report: RiskReport,
    ) -> List[Dict[str, Any]]:
        """
        Generate a prioritized remediation plan.
        """

        recommendations = []

        for index, finding in enumerate(
            self.prioritize_findings(report),
            start=1,
        ):

            recommendations.append(
                {
                    "priority": index,
                    "title": finding.finding.title,
                    "severity": finding.finding.severity,
                    "risk_score": finding.score,
                    "recommendation": (
                        finding.finding.recommendation
                    ),
                }
            )

        return recommendations

    # ---------------------------------------------------------
    # Executive Summary
    # ---------------------------------------------------------

    def executive_summary(
        self,
        report: RiskReport,
    ) -> Dict[str, Any]:
        """
        Generate a concise management-level summary.
        """

        endpoint = (
            report.validation_report
            .execution_report
            .plan
            .endpoint
            .endpoint
        )

        top_findings = self.highest_risk_findings(
            report,
            limit=3,
        )

        return {
            "endpoint": (
                f"{endpoint.method} {endpoint.path}"
            ),
            "overall_score": report.overall_score,
            "overall_rating": report.overall_rating,
            "total_findings": len(report.findings),
            "critical_findings": sum(
                1
                for finding in report.findings
                if finding.priority == "CRITICAL"
            ),
            "top_findings": [
                finding.finding.title
                for finding in top_findings
            ],
        }

    # ---------------------------------------------------------
    # Risk Distribution
    # ---------------------------------------------------------

    def risk_distribution(
        self,
        report: RiskReport,
    ) -> Dict[str, float]:
        """
        Calculate the percentage distribution of
        finding priorities.
        """

        total = len(report.findings)

        if total == 0:

            return {
                "CRITICAL": 0.0,
                "HIGH": 0.0,
                "MEDIUM": 0.0,
                "LOW": 0.0,
            }

        counts = self.priority_breakdown(
            report
        )

        return {
            priority: round(
                (count / total) * 100,
                2,
            )
            for priority, count in counts.items()
        }

    # ---------------------------------------------------------
    # Overall Recommendation
    # ---------------------------------------------------------

    def overall_recommendation(
        self,
        report: RiskReport,
    ) -> str:
        """
        Generate an overall recommendation based
        on the endpoint's risk rating.
        """

        recommendations = {
            "CRITICAL": (
                "Immediate remediation is strongly "
                "recommended before deployment."
            ),
            "HIGH": (
                "Address high-risk findings as a "
                "priority before release."
            ),
            "MEDIUM": (
                "Resolve findings during the current "
                "development cycle."
            ),
            "LOW": (
                "Address findings as part of routine "
                "security maintenance."
            ),
        }

        return recommendations.get(
            report.overall_rating,
            recommendations["LOW"],
        )
    # ---------------------------------------------------------
    # Serialization
    # ---------------------------------------------------------

    def finding_to_dict(
        self,
        finding: RiskFinding,
    ) -> Dict[str, Any]:
        """
        Convert a RiskFinding into a JSON-serializable dictionary.
        """

        return {
            "title": finding.finding.title,
            "owasp_category": finding.finding.owasp_category,
            "severity": finding.finding.severity,
            "confidence": finding.finding.confidence,
            "score": finding.score,
            "priority": finding.priority,
            "rationale": finding.rationale,
            "recommendation": (
                finding.finding.recommendation
            ),
            "description": (
                finding.finding.description
            ),
            "evidence": (
                finding.finding.evidence
            ),
        }

    def report_to_dict(
        self,
        report: RiskReport,
    ) -> Dict[str, Any]:
        """
        Convert a RiskReport into a dictionary.
        """

        endpoint = (
            report.validation_report
            .execution_report
            .plan
            .endpoint
            .endpoint
        )

        return {
            "endpoint": {
                "method": endpoint.method,
                "path": endpoint.path,
            },
            "assessed_at": report.assessed_at,
            "overall_score": report.overall_score,
            "overall_rating": report.overall_rating,
            "metrics": self.risk_metrics(report),
            "executive_summary": self.executive_summary(
                report
            ),
            "overall_recommendation": (
                self.overall_recommendation(
                    report
                )
            ),
            "findings": [
                self.finding_to_dict(finding)
                for finding in self.prioritize_findings(
                    report
                )
            ],
        }

    # ---------------------------------------------------------
    # Export
    # ---------------------------------------------------------

    def export_report(
        self,
        report: RiskReport,
        output_file: str,
    ) -> None:
        """
        Export a single risk report.
        """

        logger.info(
            "Exporting risk report to %s",
            output_file,
        )

        with open(
            output_file,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                self.report_to_dict(report),
                file,
                indent=4,
            )

    def export_reports(
        self,
        reports: List[RiskReport],
        output_file: str,
    ) -> None:
        """
        Export multiple risk reports.
        """

        logger.info(
            "Exporting %d risk reports.",
            len(reports),
        )

        exported = [
            self.report_to_dict(report)
            for report in reports
        ]

        with open(
            output_file,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                exported,
                file,
                indent=4,
            )

    # ---------------------------------------------------------
    # Batch Risk Assessment
    # ---------------------------------------------------------

    def score_reports(
        self,
        reports: List[ValidationReport],
    ) -> List[RiskReport]:
        """
        Score multiple validation reports.
        """

        risk_reports: List[RiskReport] = []

        logger.info(
            "Scoring %d validation reports.",
            len(reports),
        )

        for report in reports:

            risk_reports.append(
                self.score_report(report)
            )

        logger.info(
            "Risk assessment completed."
        )

        return risk_reports

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------

    def generate_summary(
        self,
        report: RiskReport,
    ) -> Dict[str, Any]:
        """
        Generate a concise summary of a risk report.
        """

        endpoint = (
            report.validation_report
            .execution_report
            .plan
            .endpoint
            .endpoint
        )

        return {
            "endpoint": (
                f"{endpoint.method} {endpoint.path}"
            ),
            "overall_score": report.overall_score,
            "overall_rating": report.overall_rating,
            "findings": len(report.findings),
            "critical_findings": sum(
                1
                for finding in report.findings
                if finding.priority == "CRITICAL"
            ),
            "highest_risk": (
                self.highest_risk_findings(
                    report,
                    limit=1,
                )[0].finding.title
                if report.findings
                else None
            ),
        }