"""
pipeline.py

API Sentinel AI Orchestration Pipeline.

This module coordinates every engine of the platform.

Pipeline:

Discovery
    ↓
Intelligence
    ↓
LLM Planner
    ↓
Security Executor
    ↓
Validation Engine
    ↓
Risk Engine
    ↓
AI Security Analyst
    ↓
Professional Report Generator
"""

from __future__ import annotations

import logging
import time

from dataclasses import dataclass
from typing import List

from scanner.discovery import (
    DiscoveryEngine,
    EndpointInfo,
)

from scanner.intelligence import (
    APIIntelligenceEngine,
    EndpointProfile,
)

from scanner.planner import (
    LLMTestPlanner,
    TestPlan,
)

from scanner.executor import (
    SecurityTestExecutor,
    ExecutionReport,
)

from scanner.validator import (
    ValidationEngine,
    ValidationReport,
)

from scanner.risk_engine import (
    RiskScoringEngine,
    RiskReport,
)

from scanner.analyst import (
    AISecurityAnalyst,
    SecurityAnalysis,
)

from scanner.report import (
    ReportGenerator,
    SecurityReport,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------
# Data Model
# ---------------------------------------------------------

@dataclass
class PipelineResult:
    """
    Complete output of an API Sentinel scan.
    """

    discovered_endpoints: List[EndpointInfo]

    endpoint_profiles: List[EndpointProfile]

    test_plans: List[TestPlan]

    execution_reports: List[ExecutionReport]

    validation_reports: List[ValidationReport]

    risk_reports: List[RiskReport]

    ai_analyses: List[SecurityAnalysis]

    final_reports: List[SecurityReport]

    scan_duration: float


# ---------------------------------------------------------
# Pipeline
# ---------------------------------------------------------

class APISentinelPipeline:
    """
    Coordinates the complete API Sentinel workflow.

    This class acts as the orchestration layer
    between all scanning engines.
    """

    def __init__(self):

        logger.info(
            "Initializing API Sentinel Pipeline..."
        )

        self.discovery = DiscoveryEngine()

        self.intelligence = APIIntelligenceEngine()

        self.planner = LLMTestPlanner()

        self.executor = SecurityTestExecutor()

        self.validator = ValidationEngine()

        self.risk = RiskScoringEngine()

        self.analyst = AISecurityAnalyst()

        self.report = ReportGenerator()

        logger.info(
            "Pipeline initialized successfully."
        )
    # ---------------------------------------------------------
    # Discovery Stage
    # ---------------------------------------------------------

    def _run_discovery(
        self,
        openapi_url: str,
    ) -> List[EndpointInfo]:
        """
        Run the Discovery Engine.
        """

        logger.info(
            "Starting Discovery Engine..."
        )

        endpoints = self.discovery.discover(
            openapi_url
        )

        logger.info(
            "Discovery complete. %d endpoints found.",
            len(endpoints),
        )

        return endpoints

    # ---------------------------------------------------------
    # Intelligence Stage
    # ---------------------------------------------------------

    def _run_intelligence(
        self,
        endpoints: List[EndpointInfo],
    ) -> List[EndpointProfile]:
        """
        Run the API Intelligence Engine.
        """

        logger.info(
            "Starting Intelligence Engine..."
        )

        profiles: List[
            EndpointProfile
        ] = []

        for endpoint in endpoints:

            profile = self.intelligence.analyze(
                endpoint
            )

            profiles.append(
                profile
            )

        logger.info(
            "Intelligence complete. %d endpoints analyzed.",
            len(profiles),
        )

        return profiles

    # ---------------------------------------------------------
    # Initial Pipeline
    # ---------------------------------------------------------

    def discover_and_analyze(
        self,
        openapi_url: str,
    ) -> List[EndpointProfile]:
        """
        Execute the first stages of the pipeline.
        """

        endpoints = self._run_discovery(
            openapi_url
        )

        return self._run_intelligence(
            endpoints
        )
    # ---------------------------------------------------------
    # Planning Stage
    # ---------------------------------------------------------

    def _run_planner(
        self,
        profiles: List[EndpointProfile],
    ) -> List[TestPlan]:
        """
        Run the LLM Test Planner.
        """

        logger.info(
            "Starting LLM Test Planner..."
        )

        plans = self.planner.create_plans(
            profiles
        )

        logger.info(
            "Planning complete. %d test plans generated.",
            len(plans),
        )

        return plans

    # ---------------------------------------------------------
    # Execution Stage
    # ---------------------------------------------------------

    def _run_executor(
        self,
        plans: List[TestPlan],
    ) -> List[ExecutionReport]:
        """
        Run the Security Test Executor.
        """

        logger.info(
            "Starting Security Test Executor..."
        )

        reports = self.executor.execute_plans(
            plans
        )

        logger.info(
            "Execution complete. %d execution reports generated.",
            len(reports),
        )

        return reports

    # ---------------------------------------------------------
    # Validation Stage
    # ---------------------------------------------------------

    def _run_validator(
        self,
        execution_reports: List[ExecutionReport],
    ) -> List[ValidationReport]:
        """
        Run the Validation Engine.
        """

        logger.info(
            "Starting Validation Engine..."
        )

        validation_reports = (
            self.validator.validate_reports(
                execution_reports
            )
        )

        logger.info(
            "Validation complete. %d validation reports generated.",
            len(validation_reports),
        )

        return validation_reports

    # ---------------------------------------------------------
    # Pipeline Through Validation
    # ---------------------------------------------------------

    def scan_until_validation(
        self,
        openapi_url: str,
    ) -> List[ValidationReport]:
        """
        Execute the pipeline through the
        Validation Engine.
        """

        profiles = self.discover_and_analyze(
            openapi_url
        )

        plans = self._run_planner(
            profiles
        )

        execution_reports = (
            self._run_executor(
                plans
            )
        )

        return self._run_validator(
            execution_reports
        )
    # ---------------------------------------------------------
    # Risk Scoring Stage
    # ---------------------------------------------------------

    def _run_risk_engine(
        self,
        validation_reports: List[ValidationReport],
    ) -> List[RiskReport]:
        """
        Run the Risk Scoring Engine.
        """

        logger.info(
            "Starting Risk Scoring Engine..."
        )

        risk_reports = (
            self.risk.score_reports(
                validation_reports
            )
        )

        logger.info(
            "Risk scoring complete. %d reports generated.",
            len(risk_reports),
        )

        return risk_reports

    # ---------------------------------------------------------
    # AI Security Analyst Stage
    # ---------------------------------------------------------

    def _run_ai_analyst(
        self,
        risk_reports: List[RiskReport],
    ) -> List[SecurityAnalysis]:
        """
        Run the AI Security Analyst.
        """

        logger.info(
            "Starting AI Security Analyst..."
        )

        analyses = (
            self.analyst.analyze_reports(
                risk_reports
            )
        )

        logger.info(
            "AI analysis complete. %d analyses generated.",
            len(analyses),
        )

        return analyses

    # ---------------------------------------------------------
    # Professional Report Generation Stage
    # ---------------------------------------------------------

    def _run_report_generator(
        self,
        risk_reports: List[RiskReport],
        analyses: List[SecurityAnalysis],
    ) -> List[SecurityReport]:
        """
        Run the Report Generator.
        """

        logger.info(
            "Starting Report Generator..."
        )

        reports = (
            self.report.generate_reports(
                risk_reports,
                analyses,
            )
        )

        logger.info(
            "Report generation complete. %d reports generated.",
            len(reports),
        )

        return reports

    # ---------------------------------------------------------
    # Pipeline Through Report Generation
    # ---------------------------------------------------------

    def scan_until_report(
        self,
        openapi_url: str,
    ) -> List[SecurityReport]:
        """
        Execute the pipeline through the
        Professional Report Generator.
        """

        validation_reports = (
            self.scan_until_validation(
                openapi_url
            )
        )

        risk_reports = (
            self._run_risk_engine(
                validation_reports
            )
        )

        analyses = (
            self._run_ai_analyst(
                risk_reports
            )
        )

        return self._run_report_generator(
            risk_reports,
            analyses,
        )
    # ---------------------------------------------------------
    # Complete Pipeline
    # ---------------------------------------------------------

    def scan(
        self,
        openapi_url: str,
    ) -> PipelineResult:
        """
        Execute the complete API Sentinel AI pipeline.

        This is the primary entry point for the
        application and orchestrates all scanning
        engines from discovery through report
        generation.
        """

        logger.info("=" * 70)
        logger.info("API Sentinel AI Scan Started")
        logger.info("=" * 70)

        start_time = time.perf_counter()

        # -------------------------------------------------
        # Discovery
        # -------------------------------------------------

        discovered_endpoints = self._run_discovery(
            openapi_url
        )

        # -------------------------------------------------
        # Intelligence
        # -------------------------------------------------

        endpoint_profiles = (
            self.intelligence.analyze_endpoints(
                discovered_endpoints
            )
        )

        # -------------------------------------------------
        # Planning
        # -------------------------------------------------

        test_plans = self._run_planner(
            endpoint_profiles
        )

        # -------------------------------------------------
        # Execution
        # -------------------------------------------------

        execution_reports = (
            self._run_executor(
                test_plans
            )
        )

        # -------------------------------------------------
        # Validation
        # -------------------------------------------------

        validation_reports = (
            self._run_validator(
                execution_reports
            )
        )

        # -------------------------------------------------
        # Risk Analysis
        # -------------------------------------------------

        risk_reports = (
            self._run_risk_engine(
                validation_reports
            )
        )

        # -------------------------------------------------
        # AI Security Analysis
        # -------------------------------------------------

        ai_analyses = (
            self._run_ai_analyst(
                risk_reports
            )
        )

        # -------------------------------------------------
        # Final Reports
        # -------------------------------------------------

        final_reports = (
            self._run_report_generator(
                risk_reports,
                ai_analyses,
            )
        )

        end_time = time.perf_counter()

        duration = round(
            end_time - start_time,
            2,
        )

        logger.info("=" * 70)
        logger.info(
            "API Sentinel AI Scan Completed in %.2f seconds.",
            duration,
        )
        logger.info("=" * 70)

        return PipelineResult(

            discovered_endpoints=discovered_endpoints,

            endpoint_profiles=endpoint_profiles,

            test_plans=test_plans,

            execution_reports=execution_reports,

            validation_reports=validation_reports,

            risk_reports=risk_reports,

            ai_analyses=ai_analyses,

            final_reports=final_reports,

            scan_duration=duration,
        )

    # ---------------------------------------------------------
    # Statistics
    # ---------------------------------------------------------

    def get_statistics(
        self,
        result: PipelineResult,
    ) -> dict:
        """
        Generate pipeline execution statistics.
        """

        return {

            "discovered_endpoints":
                len(result.discovered_endpoints),

            "endpoint_profiles":
                len(result.endpoint_profiles),

            "test_plans":
                len(result.test_plans),

            "execution_reports":
                len(result.execution_reports),

            "validation_reports":
                len(result.validation_reports),

            "risk_reports":
                len(result.risk_reports),

            "ai_analyses":
                len(result.ai_analyses),

            "final_reports":
                len(result.final_reports),

            "scan_duration":
                result.scan_duration,
        }
    # ---------------------------------------------------------
    # Health Check
    # ---------------------------------------------------------

    def health_check(self) -> bool:
        """
        Verify that all pipeline components have been
        initialized successfully.
        """

        components = [

            self.discovery,
            self.intelligence,
            self.planner,
            self.executor,
            self.validator,
            self.risk,
            self.analyst,
            self.report,

        ]

        healthy = all(
            component is not None
            for component in components
        )

        if healthy:

            logger.info(
                "Pipeline health check passed."
            )

        else:

            logger.error(
                "Pipeline health check failed."
            )

        return healthy

    # ---------------------------------------------------------
    # Reset Pipeline
    # ---------------------------------------------------------

    def reset(self) -> None:
        """
        Reinitialize every engine.

        Useful for long-running dashboard sessions.
        """

        logger.info(
            "Resetting API Sentinel Pipeline..."
        )

        self.__init__()

    # ---------------------------------------------------------
    # Version Information
    # ---------------------------------------------------------

    @staticmethod
    def version() -> str:
        """
        Current API Sentinel version.
        """

        return "API Sentinel AI v1.0"

    # ---------------------------------------------------------
    # Safe Scan
    # ---------------------------------------------------------

    def scan_safe(
        self,
        openapi_url: str,
    ) -> PipelineResult | None:
        """
        Execute the complete scan while
        handling unexpected failures.
        """

        try:

            return self.scan(
                openapi_url
            )

        except Exception as error:

            logger.exception(
                "Pipeline execution failed."
            )

            logger.error(
                str(error)
            )

            return None