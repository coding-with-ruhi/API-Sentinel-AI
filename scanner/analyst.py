"""
analyst.py

AI Security Analyst for API Sentinel AI.

This module converts structured risk reports into
human-readable security assessments using an LLM.

Responsibilities
----------------
1. Explain vulnerabilities.
2. Describe business impact.
3. Recommend remediations.
4. Generate executive summaries.
5. Produce developer-friendly security reports.

The AI Analyst NEVER discovers vulnerabilities.
It only explains validated findings.
"""

from __future__ import annotations

import json
import logging

from dataclasses import dataclass
from typing import Any, Dict, List

import ollama

from scanner.risk_engine import (
    RiskFinding,
    RiskReport,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

DEFAULT_MODEL = "llama3.2:3b"

DEFAULT_TEMPERATURE = 0.2


# ---------------------------------------------------------
# Data Models
# ---------------------------------------------------------

@dataclass
class SecurityAnalysis:
    """
    AI-generated security assessment.
    """

    executive_summary: str

    technical_summary: str

    business_impact: str

    remediation_plan: str

    secure_coding_advice: str

    conclusion: str


# ---------------------------------------------------------
# Exceptions
# ---------------------------------------------------------

class AnalystError(Exception):
    """Base analyst exception."""


class LLMAnalysisError(AnalystError):
    """Raised when the LLM fails."""


# ---------------------------------------------------------
# AI Security Analyst
# ---------------------------------------------------------

class AISecurityAnalyst:
    """
    Generate AI-powered explanations for
    validated security findings.
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        temperature: float = DEFAULT_TEMPERATURE,
    ):

        self.model = model
        self.temperature = temperature

        logger.info(
            "AI Security Analyst initialized."
        )

    # -----------------------------------------------------
    # Public API
    # -----------------------------------------------------

    def analyze(
        self,
        report: RiskReport,
    ) -> SecurityAnalysis:
        """
        Generate an AI security analysis from
        a RiskReport.
        """

        prompt = self._build_prompt(report)

        response = self._query_llm(prompt)

        return self._parse_response(response)

    # -----------------------------------------------------
    # Internal Methods
    # -----------------------------------------------------

    def _build_prompt(
        self,
        report: RiskReport,
    ) -> str:
        raise NotImplementedError

    def _query_llm(
        self,
        prompt: str,
    ) -> str:
        raise NotImplementedError

    def _parse_response(
        self,
        response: str,
    ) -> SecurityAnalysis:
        raise NotImplementedError
    # ---------------------------------------------------------
    # Prompt Builder
    # ---------------------------------------------------------

    def _build_prompt(
        self,
        report: RiskReport,
    ) -> str:
        """
        Build the complete prompt for the AI Security Analyst.
        """

        return (
            self._system_prompt()
            + "\n\n"
            + self._risk_context(report)
        )

    # ---------------------------------------------------------
    # System Prompt
    # ---------------------------------------------------------

    def _system_prompt(
        self,
    ) -> str:
        """
        Define the AI Security Analyst's role and expected output.
        """

        return """
You are a Senior API Security Consultant.

You are given the output of an automated API security scanner.

Your responsibilities are:

1. Explain the identified vulnerabilities.
2. Describe their technical impact.
3. Describe their business impact.
4. Recommend practical remediation steps.
5. Provide secure coding guidance.
6. Write clearly for software developers.

Do NOT invent vulnerabilities.

Only analyze the findings provided.

Return ONLY valid JSON.

The JSON MUST have exactly this structure:

{
    "executive_summary": "...",
    "technical_summary": "...",
    "business_impact": "...",
    "remediation_plan": "...",
    "secure_coding_advice": "...",
    "conclusion": "..."
}
"""

    # ---------------------------------------------------------
    # Risk Report Context
    # ---------------------------------------------------------

    def _risk_context(
        self,
        report: RiskReport,
    ) -> str:
        """
        Convert the RiskReport into structured context for the LLM.
        """

        endpoint = (
            report.validation_report
            .execution_report
            .plan
            .endpoint
            .endpoint
        )

        findings = [
            {
                "title": finding.finding.title,
                "owasp_category": (
                    finding.finding.owasp_category
                ),
                "severity": (
                    finding.finding.severity
                ),
                "confidence": (
                    finding.finding.confidence
                ),
                "risk_score": finding.score,
                "priority": finding.priority,
                "description": (
                    finding.finding.description
                ),
                "recommendation": (
                    finding.finding.recommendation
                ),
                "evidence": (
                    finding.finding.evidence
                ),
            }
            for finding in report.findings
        ]

        payload = {
            "endpoint": {
                "method": endpoint.method,
                "path": endpoint.path,
            },
            "overall_score": report.overall_score,
            "overall_rating": report.overall_rating,
            "findings": findings,
        }

        return (
            "Risk Report:\n\n"
            + json.dumps(
                payload,
                indent=4,
            )
        )
    # ---------------------------------------------------------
    # LLM Communication
    # ---------------------------------------------------------

    def _query_llm(
        self,
        prompt: str,
    ) -> str:
        """
        Send the prompt to the local Ollama model.
        """

        try:

            response = ollama.chat(
                model=self.model,
                messages=[
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                options={
                    "temperature": self.temperature,
                },
            )

            return response["message"]["content"]

        except Exception as exc:

            logger.exception(
                "LLM request failed."
            )

            raise LLMAnalysisError(
                str(exc)
            ) from exc

    # ---------------------------------------------------------
    # Response Parsing
    # ---------------------------------------------------------

    def _parse_response(
        self,
        response: str,
    ) -> SecurityAnalysis:
        """
        Parse the JSON returned by the LLM.
        """

        try:

            payload = self._extract_json(
                response
            )

            return SecurityAnalysis(
                executive_summary=payload.get(
                    "executive_summary",
                    "",
                ),
                technical_summary=payload.get(
                    "technical_summary",
                    "",
                ),
                business_impact=payload.get(
                    "business_impact",
                    "",
                ),
                remediation_plan=payload.get(
                    "remediation_plan",
                    "",
                ),
                secure_coding_advice=payload.get(
                    "secure_coding_advice",
                    "",
                ),
                conclusion=payload.get(
                    "conclusion",
                    "",
                ),
            )

        except Exception as exc:

            logger.exception(
                "Failed to parse analysis."
            )

            raise LLMAnalysisError(
                str(exc)
            ) from exc

    # ---------------------------------------------------------
    # JSON Extraction
    # ---------------------------------------------------------

    def _extract_json(
        self,
        response: str,
    ) -> Dict[str, Any]:
        """
        Extract the JSON object from an LLM response.
        """

        start = response.find("{")

        end = response.rfind("}")

        if start == -1 or end == -1:

            raise LLMAnalysisError(
                "No JSON object found."
            )

        json_text = response[
            start:end + 1
        ]

        return json.loads(json_text)

    # ---------------------------------------------------------
    # Fallback Analysis
    # ---------------------------------------------------------

    def _fallback_analysis(
        self,
        report: RiskReport,
    ) -> SecurityAnalysis:
        """
        Generate a deterministic analysis when
        the LLM is unavailable.
        """

        endpoint = (
            report.validation_report
            .execution_report
            .plan
            .endpoint
            .endpoint
        )

        top_findings = sorted(
            report.findings,
            key=lambda finding: finding.score,
            reverse=True,
        )[:3]

        finding_titles = [
            finding.finding.title
            for finding in top_findings
        ]

        return SecurityAnalysis(
            executive_summary=(
                f"The endpoint "
                f"{endpoint.method} {endpoint.path} "
                f"received an overall "
                f"{report.overall_rating} "
                f"risk rating with "
                f"{len(report.findings)} "
                f"validated findings."
            ),
            technical_summary=(
                "Top findings: "
                + ", ".join(finding_titles)
                if finding_titles
                else "No significant findings."
            ),
            business_impact=(
                "Validated findings may affect "
                "the confidentiality, integrity, "
                "or availability of the API."
            ),
            remediation_plan=(
                "Prioritize remediation based on "
                "the calculated risk scores."
            ),
            secure_coding_advice=(
                "Apply secure coding practices, "
                "validate inputs, enforce "
                "authorization, and use the "
                "OWASP API Security Top 10 "
                "as guidance."
            ),
            conclusion=(
                "Fallback analysis generated "
                "because the AI model was "
                "unavailable."
            ),
        )

    # ---------------------------------------------------------
    # Safe Analysis Entry Point
    # ---------------------------------------------------------

    def analyze_safe(
        self,
        report: RiskReport,
    ) -> SecurityAnalysis:
        """
        Safely generate an AI analysis.
        Falls back to deterministic output if
        the LLM cannot be used.
        """

        try:

            return self.analyze(
                report
            )

        except AnalystError as exc:

            logger.exception(
                "AI analysis failed: %s",
                exc,
            )

            return self._fallback_analysis(
                report
            )
    # ---------------------------------------------------------
    # Executive Summary
    # ---------------------------------------------------------

    def executive_summary(
        self,
        analysis: SecurityAnalysis,
    ) -> str:
        """
        Return the executive summary section.
        """

        return analysis.executive_summary.strip()

    # ---------------------------------------------------------
    # Technical Analysis
    # ---------------------------------------------------------

    def technical_analysis(
        self,
        analysis: SecurityAnalysis,
    ) -> str:
        """
        Return the technical explanation.
        """

        return analysis.technical_summary.strip()

    # ---------------------------------------------------------
    # Business Impact
    # ---------------------------------------------------------

    def business_impact(
        self,
        analysis: SecurityAnalysis,
    ) -> str:
        """
        Return the business impact section.
        """

        return analysis.business_impact.strip()

    # ---------------------------------------------------------
    # Remediation Guidance
    # ---------------------------------------------------------

    def remediation(
        self,
        analysis: SecurityAnalysis,
    ) -> str:
        """
        Return remediation recommendations.
        """

        return analysis.remediation_plan.strip()

    # ---------------------------------------------------------
    # Secure Coding Guidance
    # ---------------------------------------------------------

    def secure_coding(
        self,
        analysis: SecurityAnalysis,
    ) -> str:
        """
        Return secure coding advice.
        """

        return analysis.secure_coding_advice.strip()

    # ---------------------------------------------------------
    # Conclusion
    # ---------------------------------------------------------

    def conclusion(
        self,
        analysis: SecurityAnalysis,
    ) -> str:
        """
        Return the report conclusion.
        """

        return analysis.conclusion.strip()

    # ---------------------------------------------------------
    # Full Analysis
    # ---------------------------------------------------------

    def analysis_to_dict(
        self,
        analysis: SecurityAnalysis,
    ) -> Dict[str, Any]:
        """
        Convert SecurityAnalysis into
        a serializable dictionary.
        """

        return {
            "executive_summary":
                self.executive_summary(analysis),

            "technical_analysis":
                self.technical_analysis(analysis),

            "business_impact":
                self.business_impact(analysis),

            "remediation":
                self.remediation(analysis),

            "secure_coding":
                self.secure_coding(analysis),

            "conclusion":
                self.conclusion(analysis),
        }

    # ---------------------------------------------------------
    # Markdown Report
    # ---------------------------------------------------------

    def generate_markdown(
        self,
        analysis: SecurityAnalysis,
    ) -> str:
        """
        Convert the analysis into a
        developer-friendly Markdown report.
        """

        lines = [

            "# AI Security Analysis",

            "",

            "## Executive Summary",
            self.executive_summary(analysis),

            "",

            "## Technical Analysis",
            self.technical_analysis(analysis),

            "",

            "## Business Impact",
            self.business_impact(analysis),

            "",

            "## Recommended Remediation",
            self.remediation(analysis),

            "",

            "## Secure Coding Advice",
            self.secure_coding(analysis),

            "",

            "## Conclusion",
            self.conclusion(analysis),

        ]

        return "\n".join(lines)
    # ---------------------------------------------------------
    # Export
    # ---------------------------------------------------------

    def export_json(
        self,
        analysis: SecurityAnalysis,
        output_file: str,
    ) -> None:
        """
        Export the AI analysis as a JSON file.
        """

        logger.info(
            "Exporting AI analysis to %s",
            output_file,
        )

        with open(
            output_file,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                self.analysis_to_dict(
                    analysis
                ),
                file,
                indent=4,
            )

    def export_markdown(
        self,
        analysis: SecurityAnalysis,
        output_file: str,
    ) -> None:
        """
        Export the AI analysis as Markdown.
        """

        logger.info(
            "Exporting Markdown report to %s",
            output_file,
        )

        with open(
            output_file,
            "w",
            encoding="utf-8",
        ) as file:

            file.write(
                self.generate_markdown(
                    analysis
                )
            )

    # ---------------------------------------------------------
    # Batch Analysis
    # ---------------------------------------------------------

    def analyze_reports(
        self,
        reports: List[RiskReport],
    ) -> List[SecurityAnalysis]:
        """
        Analyze multiple risk reports.
        """

        analyses: List[
            SecurityAnalysis
        ] = []

        logger.info(
            "Analyzing %d reports.",
            len(reports),
        )

        for report in reports:

            analyses.append(
                self.analyze_safe(
                    report
                )
            )

        logger.info(
            "Batch analysis completed."
        )

        return analyses

    # ---------------------------------------------------------
    # Batch Export
    # ---------------------------------------------------------

    def export_analysis_collection(
        self,
        analyses: List[SecurityAnalysis],
        output_file: str,
    ) -> None:
        """
        Export multiple AI analyses.
        """

        logger.info(
            "Exporting %d analyses.",
            len(analyses),
        )

        payload = [

            self.analysis_to_dict(
                analysis
            )

            for analysis in analyses

        ]

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
        analysis: SecurityAnalysis,
    ) -> Dict[str, str]:
        """
        Generate a concise summary of the AI analysis.
        """

        return {

            "executive_summary":
                analysis.executive_summary,

            "business_impact":
                analysis.business_impact,

            "remediation":
                analysis.remediation_plan,

            "conclusion":
                analysis.conclusion,

        }