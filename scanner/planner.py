"""
planner.py

LLM Test Planner for API Sentinel AI.

This module is responsible for converting intelligent endpoint
profiles into structured security test plans using a local
Large Language Model (LLM) running through Ollama.

Responsibilities
----------------
1. Build contextual prompts from endpoint intelligence.
2. Query the local LLM.
3. Generate structured security test plans.
4. Validate and normalize LLM responses.
5. Provide fallback plans if the LLM fails.

The planner NEVER executes security tests.
Execution is delegated to the Security Test Executor.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import ollama

from scanner.intelligence import EndpointProfile

logger = logging.getLogger(__name__)


# ---------------------------------------------------------
# Planner Configuration
# ---------------------------------------------------------

DEFAULT_MODEL = "llama3.2:3b"

DEFAULT_TEMPERATURE = 0.2

DEFAULT_TIMEOUT = 120


# ---------------------------------------------------------
# Data Models
# ---------------------------------------------------------

@dataclass
class TestCase:
    """
    Represents a single security test generated
    by the LLM.
    """

    title: str

    description: str

    owasp_category: str

    priority: str

    objective: str

    execution_steps: List[str] = field(default_factory=list)

    expected_result: str = ""

    payload_examples: List[str] = field(default_factory=list)


@dataclass
class TestPlan:
    """
    Collection of security tests for one endpoint.
    """

    endpoint: EndpointProfile

    generated_by: str

    reasoning: str

    overall_risk: str

    test_cases: List[TestCase] = field(default_factory=list)


# ---------------------------------------------------------
# Exceptions
# ---------------------------------------------------------

class PlannerError(Exception):
    """Base planner exception."""


class LLMCommunicationError(PlannerError):
    """Raised when communication with Ollama fails."""


class InvalidLLMResponseError(PlannerError):
    """Raised when the LLM returns invalid data."""


# ---------------------------------------------------------
# LLM Test Planner
# ---------------------------------------------------------

class LLMTestPlanner:
    """
    AI-powered planner responsible for generating
    security test plans from endpoint intelligence.
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        temperature: float = DEFAULT_TEMPERATURE,
    ) -> None:

        self.model = model

        self.temperature = temperature

        logger.info(
            "Initialized LLM Test Planner using model '%s'",
            model,
        )

    # -----------------------------------------------------
    # Public API
    # -----------------------------------------------------

    def generate_plan(
        self,
        profile: EndpointProfile,
    ) -> TestPlan:
        """
        Generate a complete security testing plan
        for a single endpoint.

        This is the main entry point used by the
        orchestration pipeline.
        """

        logger.info(
            "Generating test plan for %s %s",
            profile.endpoint.method,
            profile.endpoint.path,
        )

        prompt = self._build_prompt(profile)

        raw_response = self._query_llm(prompt)

        return self._parse_response(
            profile,
            raw_response,
        )

    # -----------------------------------------------------
    # Internal Methods
    # -----------------------------------------------------

    def _build_prompt(
        self,
        profile: EndpointProfile,
    ) -> str:
        raise NotImplementedError

    def _query_llm(
        self,
        prompt: str,
    ) -> str:
        raise NotImplementedError

    def _parse_response(
        self,
        profile: EndpointProfile,
        response: str,
    ) -> TestPlan:
        raise NotImplementedError
# ---------------------------------------------------------
# Prompt Construction
# ---------------------------------------------------------

    def _build_prompt(
        self,
        profile: EndpointProfile,
    ) -> str:
        """
        Build the complete prompt sent to the LLM.
        """

        system_prompt = self._system_prompt()

        endpoint_context = self._endpoint_context(profile)

        return (
            f"{system_prompt}\n\n"
            f"{endpoint_context}\n\n"
            "Generate a security testing plan."
        )

    # ---------------------------------------------------------

    def _system_prompt(
        self,
    ) -> str:
        """
        System prompt that defines the LLM's role.
        """

        return """
You are an experienced API Security Engineer.

Your responsibility is to generate a professional API security
testing plan.

Rules:

- Think like an OWASP API penetration tester.
- Only recommend realistic security tests.
- Prioritize critical risks first.
- Never invent endpoint details.
- Use the supplied endpoint information only.
- Return ONLY valid JSON.
- Do NOT include markdown.
- Do NOT include explanations outside JSON.

The JSON format MUST be:

{
  "reasoning": "...",
  "overall_risk": "...",
  "test_cases": [
    {
      "title": "...",
      "description": "...",
      "owasp_category": "...",
      "priority": "...",
      "objective": "...",
      "execution_steps": [
        "...",
        "..."
      ],
      "expected_result": "...",
      "payload_examples": [
        "...",
        "..."
      ]
    }
  ]
}
""".strip()

    # ---------------------------------------------------------

    def _endpoint_context(
        self,
        profile: EndpointProfile,
    ) -> str:
        """
        Convert the EndpointProfile into a structured
        prompt section.
        """

        endpoint = profile.endpoint

        context = {
            "method": endpoint.method,
            "path": endpoint.path,
            "resource": profile.resource,
            "crud_operation": profile.crud_operation,
            "category": profile.endpoint_category,
            "authentication": profile.authentication,
            "authentication_required": profile.authentication_required,
            "sensitive": profile.sensitive,
            "sensitivity_reason": profile.sensitivity_reason,
            "business_criticality": profile.business_criticality,
            "likely_owasp": profile.likely_owasp,
            "confidence": profile.confidence,
            "parameters": endpoint.parameters,
            "request_body": endpoint.request_body,
            "responses": endpoint.responses,
        }

        return (
            "Endpoint Intelligence\n"
            "=====================\n"
            f"{json.dumps(context, indent=4)}"
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

        Returns
        -------
        str
            Raw response from the LLM.
        """

        logger.info("Sending prompt to Ollama...")

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

        except Exception as exc:
            logger.exception("Failed to communicate with Ollama.")
            raise LLMCommunicationError(str(exc)) from exc

        try:
            content = response["message"]["content"].strip()

        except (KeyError, TypeError) as exc:
            raise InvalidLLMResponseError(
                "Ollama returned an unexpected response format."
            ) from exc

        logger.info("Received response from Ollama.")

        return content

    # ---------------------------------------------------------
    # Response Parsing
    # ---------------------------------------------------------

    def _parse_response(
        self,
        profile: EndpointProfile,
        response: str,
    ) -> TestPlan:
        """
        Parse the JSON returned by the LLM into a
        structured TestPlan object.
        """

        logger.info("Parsing LLM response...")

        data = self._extract_json(response)

        test_cases: List[TestCase] = []

        for item in data.get("test_cases", []):

            test_cases.append(
                TestCase(
                    title=item.get("title", ""),
                    description=item.get("description", ""),
                    owasp_category=item.get("owasp_category", ""),
                    priority=item.get("priority", ""),
                    objective=item.get("objective", ""),
                    execution_steps=item.get(
                        "execution_steps",
                        [],
                    ),
                    expected_result=item.get(
                        "expected_result",
                        "",
                    ),
                    payload_examples=item.get(
                        "payload_examples",
                        [],
                    ),
                )
            )

        return TestPlan(
            endpoint=profile,
            generated_by=self.model,
            reasoning=data.get("reasoning", ""),
            overall_risk=data.get(
                "overall_risk",
                "UNKNOWN",
            ),
            test_cases=test_cases,
        )

    # ---------------------------------------------------------
    # JSON Extraction
    # ---------------------------------------------------------

    def _extract_json(
        self,
        response: str,
    ) -> Dict[str, Any]:
        """
        Extract valid JSON from an LLM response.

        Handles situations where the model adds
        explanations before or after the JSON.
        """

        start = response.find("{")
        end = response.rfind("}")

        if start == -1 or end == -1:

            raise InvalidLLMResponseError(
                "No JSON object found in LLM response."
            )

        json_text = response[start : end + 1]

        try:
            return json.loads(json_text)

        except json.JSONDecodeError as exc:

            logger.exception("Invalid JSON returned.")

            raise InvalidLLMResponseError(
                "LLM returned malformed JSON."
            ) from exc
    # ---------------------------------------------------------
    # Fallback Planning
    # ---------------------------------------------------------

    def _fallback_plan(
        self,
        profile: EndpointProfile,
    ) -> TestPlan:
        """
        Generate a deterministic fallback test plan if
        the LLM is unavailable or returns invalid data.
        """

        logger.warning(
            "Generating fallback security test plan."
        )

        test_cases: List[TestCase] = []

        for owasp in profile.likely_owasp:

            test_cases.append(
                TestCase(
                    title=f"{owasp} Security Test",
                    description=f"Validate endpoint against {owasp}.",
                    owasp_category=owasp,
                    priority=self._priority_from_criticality(
                        profile.business_criticality
                    ),
                    objective=f"Identify potential {owasp} weaknesses.",
                    execution_steps=[
                        "Prepare request.",
                        "Execute security payload.",
                        "Analyze response.",
                    ],
                    expected_result="Endpoint securely rejects malicious input.",
                    payload_examples=[],
                )
            )

        if not test_cases:

            test_cases.append(
                TestCase(
                    title="General Security Test",
                    description="Run baseline security assessment.",
                    owasp_category="General",
                    priority="MEDIUM",
                    objective="Detect common API security issues.",
                    execution_steps=[
                        "Send request.",
                        "Observe response.",
                    ],
                    expected_result="Endpoint behaves securely.",
                    payload_examples=[],
                )
            )

        return TestPlan(
            endpoint=profile,
            generated_by="Fallback Planner",
            reasoning="Fallback deterministic plan generated.",
            overall_risk=profile.business_criticality,
            test_cases=test_cases,
        )

    # ---------------------------------------------------------
    # Priority Mapping
    # ---------------------------------------------------------

    def _priority_from_criticality(
        self,
        criticality: str,
    ) -> str:
        """
        Convert business criticality into test priority.
        """

        mapping = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
        }

        return mapping.get(
            criticality.upper(),
            "MEDIUM",
        )

    # ---------------------------------------------------------
    # Safe Planner Entry Point
    # ---------------------------------------------------------

    def create_plan(
        self,
        profile: EndpointProfile,
    ) -> TestPlan:
        """
        Safely generate a test plan.

        If the LLM fails for any reason,
        automatically fall back to the deterministic
        planner.
        """

        try:

            return self.generate_plan(profile)

        except PlannerError as exc:

            logger.exception(
                "Planner failed: %s",
                exc,
            )

            return self._fallback_plan(profile)
    # ---------------------------------------------------------
    # Serialization
    # ---------------------------------------------------------

    def plan_to_dict(
        self,
        plan: TestPlan,
    ) -> Dict[str, Any]:
        """
        Convert a TestPlan into a JSON-serializable dictionary.
        """

        return {
            "endpoint": {
                "method": plan.endpoint.endpoint.method,
                "path": plan.endpoint.endpoint.path,
            },
            "generated_by": plan.generated_by,
            "reasoning": plan.reasoning,
            "overall_risk": plan.overall_risk,
            "test_cases": [
                {
                    "title": test.title,
                    "description": test.description,
                    "owasp_category": test.owasp_category,
                    "priority": test.priority,
                    "objective": test.objective,
                    "execution_steps": test.execution_steps,
                    "expected_result": test.expected_result,
                    "payload_examples": test.payload_examples,
                }
                for test in plan.test_cases
            ],
        }

    # ---------------------------------------------------------
    # Export Single Plan
    # ---------------------------------------------------------

    def export_plan(
        self,
        plan: TestPlan,
        output_file: str,
    ) -> None:
        """
        Export a single TestPlan to JSON.
        """

        logger.info(
            "Exporting test plan to %s",
            output_file,
        )

        with open(
            output_file,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                self.plan_to_dict(plan),
                file,
                indent=4,
            )

    # ---------------------------------------------------------
    # Export Multiple Plans
    # ---------------------------------------------------------

    def export_all_plans(
        self,
        plans: List[TestPlan],
        output_file: str,
    ) -> None:
        """
        Export multiple TestPlans into one JSON file.
        """

        logger.info(
            "Exporting %d plans",
            len(plans),
        )

        exported = [
            self.plan_to_dict(plan)
            for plan in plans
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
    # Summary
    # ---------------------------------------------------------

    def generate_summary(
        self,
        plan: TestPlan,
    ) -> Dict[str, Any]:
        """
        Generate a concise summary of the test plan.
        """

        return {
            "endpoint": (
                f"{plan.endpoint.endpoint.method} "
                f"{plan.endpoint.endpoint.path}"
            ),
            "overall_risk": plan.overall_risk,
            "tests_generated": len(plan.test_cases),
            "critical_tests": sum(
                1
                for test in plan.test_cases
                if test.priority.upper() == "CRITICAL"
            ),
            "high_priority_tests": sum(
                1
                for test in plan.test_cases
                if test.priority.upper() == "HIGH"
            ),
            "generated_by": plan.generated_by,
        }

    # ---------------------------------------------------------
    # Batch Planning
    # ---------------------------------------------------------

    def create_plans(
        self,
        profiles: List[EndpointProfile],
    ) -> List[TestPlan]:
        """
        Generate test plans for multiple endpoints.
        """

        plans: List[TestPlan] = []

        logger.info(
            "Generating plans for %d endpoints",
            len(profiles),
        )

        for profile in profiles:

            plans.append(
                self.create_plan(profile)
            )

        logger.info(
            "Successfully generated %d plans",
            len(plans),
        )

        return plans