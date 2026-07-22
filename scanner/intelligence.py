"""
scanner/intelligence.py

API Intelligence Engine

This module enriches API endpoint information discovered by the
Discovery Engine.

Responsibilities
----------------
- Resource detection
- CRUD operation identification
- Authentication analysis
- Sensitive endpoint detection
- Business criticality estimation
- OWASP API Top 10 mapping
- Endpoint profile generation

This module performs deterministic analysis only.
No LLM calls occur here.
"""

from __future__ import annotations

import logging

from dataclasses import dataclass, field
from typing import Any, Dict, List

from scanner.discovery import (
    APISpecification,
    EndpointInfo,
)

logger = logging.getLogger(__name__)


# -------------------------------------------------------------
# Constants
# -------------------------------------------------------------

CRUD_MAPPING = {
    "GET": "READ",
    "POST": "CREATE",
    "PUT": "UPDATE",
    "PATCH": "UPDATE",
    "DELETE": "DELETE",
}


# -------------------------------------------------------------
# Endpoint Intelligence Profile
# -------------------------------------------------------------

@dataclass
class EndpointProfile:
    """
    Enriched endpoint representation used by the
    remaining security pipeline.
    """

    endpoint: EndpointInfo

    resource: str

    crud_operation: str

    endpoint_category: str

    authentication: str

    authentication_required: bool

    sensitive: bool

    sensitivity_reason: str

    business_criticality: str

    likely_owasp: List[str] = field(default_factory=list)

    confidence: float = 0.0


# -------------------------------------------------------------
# API Intelligence Engine
# -------------------------------------------------------------

class APIIntelligenceEngine:
    """
    Performs deterministic analysis of API endpoints.

    Input
    -----
    APISpecification

    Output
    ------
    List[EndpointProfile]
    """

    def __init__(
        self,
        specification: APISpecification,
    ) -> None:

        self.specification = specification

        self.endpoint_profiles: List[
            EndpointProfile
        ] = []

    # ---------------------------------------------------------
    # Main Pipeline
    # ---------------------------------------------------------

    def analyze(self) -> List[EndpointProfile]:
        """
        Analyze every endpoint discovered by the
        Discovery Engine.
        """

        logger.info(
            "Starting API Intelligence analysis..."
        )

        for endpoint in self.specification.endpoints:

            profile = self._analyze_endpoint(
                endpoint
            )

            self.endpoint_profiles.append(
                profile
            )

        logger.info(
            "Generated %d endpoint profiles.",
            len(self.endpoint_profiles),
        )

        return self.endpoint_profiles

    # ---------------------------------------------------------
    # Endpoint Analysis
    # ---------------------------------------------------------

    def analyze_endpoints(
    self,
    endpoints: List[EndpointInfo],
) -> List[EndpointProfile]:
        """
        Perform deterministic analysis of
        a single endpoint.
        """

        resource = self._detect_resource(
            endpoint
        )

        crud = self._detect_crud_operation(
            endpoint
        )

        category = self._categorize_endpoint(
            endpoint,
            resource,
        )

        authentication = self._detect_authentication(
            endpoint
        )

        auth_required = authentication != "Public"

        sensitive, reason = (
            self._detect_sensitive_endpoint(
                endpoint,
                resource,
            )
        )

        criticality = (
            self._estimate_business_criticality(
                endpoint,
                resource,
                sensitive,
            )
        )

        owasp = self._map_owasp_categories(
            endpoint,
            resource,
            crud,
            sensitive,
        )

        confidence = self._calculate_confidence(
            endpoint,
            resource,
            sensitive,
            authentication,
        )

        return EndpointProfile(
            endpoint=endpoint,
            resource=resource,
            crud_operation=crud,
            endpoint_category=category,
            authentication=authentication,
            authentication_required=auth_required,
            sensitive=sensitive,
            sensitivity_reason=reason,
            business_criticality=criticality,
            likely_owasp=owasp,
            confidence=confidence,
        )

    # ---------------------------------------------------------
    # Placeholder Methods
    # ---------------------------------------------------------

    def _detect_resource(
        self,
        endpoint: EndpointInfo,
    ) -> str:
        raise NotImplementedError

    def _detect_crud_operation(
        self,
        endpoint: EndpointInfo,
    ) -> str:
        raise NotImplementedError

    def _categorize_endpoint(
        self,
        endpoint: EndpointInfo,
        resource: str,
    ) -> str:
        raise NotImplementedError

    def _detect_authentication(
        self,
        endpoint: EndpointInfo,
    ) -> str:
        raise NotImplementedError

    def _detect_sensitive_endpoint(
        self,
        endpoint: EndpointInfo,
        resource: str,
    ):
        raise NotImplementedError

    def _estimate_business_criticality(
        self,
        endpoint: EndpointInfo,
        resource: str,
        sensitive: bool,
    ) -> str:
        raise NotImplementedError

    def _map_owasp_categories(
        self,
        endpoint: EndpointInfo,
        resource: str,
        crud: str,
        sensitive: bool,
    ) -> List[str]:
        raise NotImplementedError

    def _calculate_confidence(
        self,
        endpoint: EndpointInfo,
        resource: str,
        sensitive: bool,
        authentication: str,
    ) -> float:
        raise NotImplementedError
    # ---------------------------------------------------------
    # Resource Detection
    # ---------------------------------------------------------

    def _detect_resource(
        self,
        endpoint: EndpointInfo,
    ) -> str:
        """
        Determine the primary resource associated with
        an endpoint based on its URL path.
        """

        path = endpoint.path.lower().strip("/")

        if not path:
            return "Root"

        # Split path into meaningful segments
        segments = [
            segment
            for segment in path.split("/")
            if segment and not segment.startswith("{")
        ]

        if not segments:
            return "Unknown"

        resource = segments[0].replace("-", " ").replace("_", " ")

        return resource.title()

    # ---------------------------------------------------------
    # CRUD Detection
    # ---------------------------------------------------------

    def _detect_crud_operation(
        self,
        endpoint: EndpointInfo,
    ) -> str:
        """
        Map HTTP methods to CRUD operations.
        """

        return CRUD_MAPPING.get(
            endpoint.method.upper(),
            "UNKNOWN",
        )

    # ---------------------------------------------------------
    # Endpoint Categorization
    # ---------------------------------------------------------

    def _categorize_endpoint(
        self,
        endpoint: EndpointInfo,
        resource: str,
    ) -> str:
        """
        Categorize endpoints into high-level functional groups.
        """

        path = endpoint.path.lower()

        category_keywords = {
            "Authentication": [
                "login",
                "logout",
                "register",
                "signup",
                "signin",
                "auth",
                "token",
                "oauth",
                "password",
                "reset",
                "verify",
            ],
            "Administration": [
                "admin",
                "management",
                "dashboard",
                "settings",
                "roles",
                "permissions",
            ],
            "User Management": [
                "user",
                "users",
                "profile",
                "account",
                "customer",
                "member",
            ],
            "Payments": [
                "payment",
                "payments",
                "billing",
                "invoice",
                "checkout",
                "transaction",
                "wallet",
            ],
            "Products": [
                "product",
                "products",
                "inventory",
                "catalog",
                "item",
                "items",
            ],
            "Orders": [
                "order",
                "orders",
                "cart",
                "purchase",
            ],
            "Files": [
                "file",
                "files",
                "upload",
                "download",
                "media",
                "image",
                "document",
            ],
            "Reports": [
                "report",
                "reports",
                "analytics",
                "metrics",
                "logs",
            ],
        }

        for category, keywords in category_keywords.items():

            if any(keyword in path for keyword in keywords):
                return category

        # Fallback based on detected resource
        return f"{resource} Management"
    # ---------------------------------------------------------
    # Authentication Detection
    # ---------------------------------------------------------

    def _detect_authentication(
        self,
        endpoint: EndpointInfo,
    ) -> str:
        """
        Detect the authentication mechanism protecting
        an endpoint.

        Returns
        -------
        str
            JWT, OAuth2, API Key, Basic Auth, or Public
        """

        if not endpoint.security:
            return "Public"

        security_text = str(endpoint.security).lower()

        if "bearer" in security_text or "jwt" in security_text:
            return "JWT"

        if "oauth" in security_text:
            return "OAuth2"

        if "apikey" in security_text or "api_key" in security_text:
            return "API Key"

        if "basic" in security_text:
            return "Basic Auth"

        return "Authenticated"

    # ---------------------------------------------------------
    # Sensitive Endpoint Detection
    # ---------------------------------------------------------

    def _detect_sensitive_endpoint(
        self,
        endpoint: EndpointInfo,
        resource: str,
    ) -> tuple[bool, str]:
        """
        Determine whether an endpoint is sensitive.

        Returns
        -------
        (bool, str)

        bool:
            Is the endpoint sensitive?

        str:
            Reason for classification.
        """

        path = endpoint.path.lower()

        keyword_map = {
            "Authentication": [
                "login",
                "logout",
                "password",
                "register",
                "signup",
                "signin",
                "token",
                "refresh",
                "reset",
                "verify",
            ],
            "Administration": [
                "admin",
                "role",
                "permission",
                "settings",
                "config",
            ],
            "User Data": [
                "user",
                "profile",
                "customer",
                "account",
                "email",
            ],
            "Financial": [
                "payment",
                "billing",
                "invoice",
                "wallet",
                "transaction",
                "checkout",
            ],
            "Files": [
                "upload",
                "download",
                "file",
                "media",
                "document",
            ],
        }

        for reason, keywords in keyword_map.items():

            if any(keyword in path for keyword in keywords):
                return True, reason

        return False, "General Endpoint"

    # ---------------------------------------------------------
    # Business Criticality
    # ---------------------------------------------------------

    def _estimate_business_criticality(
        self,
        endpoint: EndpointInfo,
        resource: str,
        sensitive: bool,
    ) -> str:
        """
        Estimate business criticality.

        Levels

        LOW

        MEDIUM

        HIGH

        CRITICAL
        """

        path = endpoint.path.lower()

        critical_keywords = [
            "payment",
            "billing",
            "wallet",
            "transaction",
            "invoice",
            "bank",
        ]

        high_keywords = [
            "login",
            "password",
            "token",
            "admin",
            "user",
            "customer",
            "account",
            "profile",
        ]

        medium_keywords = [
            "order",
            "cart",
            "product",
            "inventory",
            "upload",
            "download",
        ]

        if any(word in path for word in critical_keywords):
            return "CRITICAL"

        if any(word in path for word in high_keywords):
            return "HIGH"

        if any(word in path for word in medium_keywords):
            return "MEDIUM"

        if sensitive:
            return "HIGH"

        return "LOW"
    # ---------------------------------------------------------
    # OWASP API Top 10 Mapping
    # ---------------------------------------------------------

    def _map_owasp_categories(
        self,
        endpoint: EndpointInfo,
        resource: str,
        crud: str,
        sensitive: bool,
    ) -> List[str]:
        """
        Predict likely OWASP API Security Top 10 risks
        for an endpoint using deterministic heuristics.
        """

        path = endpoint.path.lower()

        categories = set()

        # API1 - Broken Object Level Authorization (BOLA)
        if "{id}" in path or "{user_id}" in path:
            categories.add("API1")

        # API2 - Broken Authentication
        if any(keyword in path for keyword in [
            "login",
            "logout",
            "token",
            "password",
            "auth",
            "register",
        ]):
            categories.add("API2")

        # API3 - Broken Object Property Level Authorization
        if resource.lower() in [
            "user",
            "customer",
            "account",
            "profile",
        ]:
            categories.add("API3")

        # API4 - Unrestricted Resource Consumption
        if crud == "CREATE":
            categories.add("API4")

        # API5 - Broken Function Level Authorization
        if "admin" in path or crud == "DELETE":
            categories.add("API5")

        # API6 - Unrestricted Access to Sensitive Business Flows
        if any(keyword in path for keyword in [
            "checkout",
            "payment",
            "wallet",
            "billing",
            "purchase",
        ]):
            categories.add("API6")

        # API7 - Server Side Request Forgery
        if any(keyword in path for keyword in [
            "url",
            "callback",
            "redirect",
            "proxy",
            "fetch",
        ]):
            categories.add("API7")

        # API8 - Security Misconfiguration
        if endpoint.authentication_required is False:
            categories.add("API8")

        # API9 - Improper Inventory Management
        if endpoint.deprecated:
            categories.add("API9")

        # API10 - Unsafe Consumption of APIs
        if any(keyword in path for keyword in [
            "external",
            "thirdparty",
            "integration",
            "webhook",
        ]):
            categories.add("API10")

        return sorted(categories)

    # ---------------------------------------------------------
    # Confidence Score
    # ---------------------------------------------------------

    def _calculate_confidence(
        self,
        endpoint: EndpointInfo,
        resource: str,
        sensitive: bool,
        authentication: str,
    ) -> float:
        """
        Estimate confidence in the generated endpoint profile.

        Returns
        -------
        float
            Confidence score between 0.0 and 1.0.
        """

        score = 0.40

        # Resource successfully detected
        if resource != "Unknown":
            score += 0.15

        # Authentication information available
        if authentication != "Public":
            score += 0.15

        # Endpoint classified as sensitive
        if sensitive:
            score += 0.15

        # Has parameters
        if endpoint.parameters:
            score += 0.05

        # Has request body
        if endpoint.request_body:
            score += 0.05

        # Has responses documented
        if endpoint.responses:
            score += 0.05

        return round(min(score, 1.0), 2)

    # ---------------------------------------------------------
    # Profile Serialization
    # ---------------------------------------------------------

    def profile_to_dict(
        self,
        profile: EndpointProfile,
    ) -> Dict[str, Any]:
        """
        Convert an EndpointProfile into a JSON-serializable
        dictionary.
        """

        return {
            "path": profile.endpoint.path,
            "method": profile.endpoint.method,
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
        }