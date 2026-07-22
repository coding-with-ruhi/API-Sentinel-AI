"""
API Sentinel AI
================

Module:
    scanner.discovery

Purpose:
    Production-grade API Discovery Engine responsible for discovering,
    downloading, validating, and parsing OpenAPI 3.x and Swagger 2.0
    specifications.

Supported Specification Formats
-------------------------------
✔ OpenAPI 3.x (JSON)
✔ OpenAPI 3.x (YAML)
✔ Swagger 2.0 (JSON)
✔ Swagger 2.0 (YAML)

Supported Discovery Endpoints
-----------------------------
/openapi.json
/swagger.json
/swagger/v1/swagger.json
/swagger/v2/swagger.json
/api-docs
/v2/api-docs
/v3/api-docs
/openapi.yaml
/openapi.yml
/swagger.yaml
/swagger.yml

This module is intentionally generic so that it works not only with
VAmPI but with most REST APIs exposing an OpenAPI or Swagger document.

Author:
    API Sentinel AI

"""

from __future__ import annotations

import json
import logging
import pathlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests
import yaml

# ----------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------

DEFAULT_TIMEOUT = 20

DISCOVERY_ENDPOINTS = [
    "/openapi.json",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.yaml",
    "/swagger.yml",
]

SUPPORTED_OPENAPI_VERSIONS = (
    "3.0",
    "3.1",
)

SUPPORTED_SWAGGER_VERSION = "2.0"

# ----------------------------------------------------------------------
# Exceptions
# ----------------------------------------------------------------------


class DiscoveryError(Exception):
    """
    Base exception raised by the discovery engine.
    """


class SpecificationNotFound(DiscoveryError):
    """
    Raised when no OpenAPI/Swagger specification can be located.
    """


class InvalidSpecification(DiscoveryError):
    """
    Raised when the downloaded document is not a valid specification.
    """


class UnsupportedSpecification(DiscoveryError):
    """
    Raised when the specification version is unsupported.
    """


# ----------------------------------------------------------------------
# Data Models
# ----------------------------------------------------------------------


@dataclass(slots=True)
class EndpointInfo:
    """
    Represents one API endpoint.

    Example
    -------
    GET /users/{id}
    """

    path: str
    method: str

    operation_id: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    parameters: List[Dict[str, Any]] = field(default_factory=list)
    request_body: Dict[str, Any] = field(default_factory=dict)

    responses: Dict[str, Any] = field(default_factory=dict)

    security: List[Dict[str, Any]] = field(default_factory=list)

    deprecated: bool = False


@dataclass(slots=True)
class APISpecification:
    """
    Normalized API specification after parsing.

    Regardless of whether the source was
    OpenAPI 3.x or Swagger 2.0,
    the rest of the scanner only interacts
    with this object.
    """

    title: str

    version: str

    specification_version: str

    base_url: str

    raw_document: Dict[str, Any]

    endpoints: List[EndpointInfo] = field(default_factory=list)


# ----------------------------------------------------------------------
# Discovery Engine
# ----------------------------------------------------------------------


class APIDiscoveryEngine:
    """
    Responsible for:

    1. Locating an OpenAPI specification.
    2. Downloading it.
    3. Validating it.
    4. Returning a normalized APISpecification object.

    Example
    -------
    >>> engine = APIDiscoveryEngine("http://localhost:5000")
    >>> spec = engine.discover()
    >>> len(spec.endpoints)
    18
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:

        self.base_url = base_url.rstrip("/")

        self.timeout = timeout

        self.session = requests.Session()

        self.session.headers.update(
            {
                "User-Agent": "API-Sentinel-AI/1.0"
            }
        )

        logger.info("Discovery Engine initialized.")

    # -------------------------------------------------------------

    def discover(self) -> APISpecification:
        """
        Public entry point.

        Returns
        -------
        APISpecification
            Parsed and normalized API specification.
        """

        logger.info("Starting API discovery...")

        spec_url = self._locate_specification()

        logger.info("Specification found: %s", spec_url)

        raw_document = self._download_specification(spec_url)

        self._validate_document(raw_document)

        return self._parse_specification(
            raw_document=raw_document,
            specification_url=spec_url,
        )
    # -------------------------------------------------------------
    # Discovery Stage 1
    # -------------------------------------------------------------

    def _locate_specification(self) -> str:
        """
        Locate an OpenAPI/Swagger specification by probing a list of
        well-known documentation endpoints.

        Strategy
        --------
        1. Try every common endpoint.
        2. Ignore failures.
        3. Return the first valid specification URL.

        Raises
        ------
        SpecificationNotFound
            If no specification endpoint can be located.
        """

        logger.info("Searching for OpenAPI specification...")

        for endpoint in DISCOVERY_ENDPOINTS:

            candidate = urljoin(f"{self.base_url}/", endpoint.lstrip("/"))

            logger.debug("Trying %s", candidate)

            if self._is_valid_specification_url(candidate):

                logger.info("Specification discovered at %s", candidate)

                return candidate

        raise SpecificationNotFound(
            "Unable to locate an OpenAPI/Swagger specification."
        )

    # -------------------------------------------------------------
    # Endpoint Validation
    # -------------------------------------------------------------

    def _is_valid_specification_url(
        self,
        url: str,
    ) -> bool:
        """
        Determine whether a URL hosts a valid API specification.

        Validation process

        1. Download document
        2. Parse JSON/YAML
        3. Check OpenAPI or Swagger keys
        """

        try:

            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
            )

        except requests.RequestException as exc:

            logger.debug("Connection failed: %s", exc)

            return False

        if response.status_code != 200:

            logger.debug(
                "%s returned HTTP %s",
                url,
                response.status_code,
            )

            return False

        try:

            document = self._decode_document(response)

        except Exception:

            logger.debug("%s is not a valid JSON/YAML document.", url)

            return False

        return self._looks_like_openapi(document)

    # -------------------------------------------------------------
    # Download Specification
    # -------------------------------------------------------------

    def _download_specification(
        self,
        specification_url: str,
    ) -> Dict[str, Any]:
        """
        Download and decode an API specification.

        Parameters
        ----------
        specification_url:
            URL returned by the discovery stage.

        Returns
        -------
        dict
            Parsed OpenAPI document.
        """

        logger.info("Downloading specification...")

        try:

            response = self.session.get(
                specification_url,
                timeout=self.timeout,
                allow_redirects=True,
            )

            response.raise_for_status()

        except requests.RequestException as exc:

            raise DiscoveryError(
                f"Unable to download specification: {exc}"
            ) from exc

        document = self._decode_document(response)

        logger.info("Specification downloaded successfully.")

        return document

    # -------------------------------------------------------------
    # Decode Specification
    # -------------------------------------------------------------

    def _decode_document(
        self,
        response: requests.Response,
    ) -> Dict[str, Any]:
        """
        Automatically decode JSON or YAML documents.

        Supports

        - application/json
        - application/yaml
        - text/yaml
        - text/plain

        Falls back gracefully if Content-Type headers
        are incorrect.
        """

        content_type = response.headers.get(
            "Content-Type",
            "",
        ).lower()

        text = response.text

        # JSON

        if "json" in content_type:

            return response.json()

        # YAML

        if "yaml" in content_type or "yml" in content_type:

            return yaml.safe_load(text)

        # Fallback

        try:

            return json.loads(text)

        except Exception:

            return yaml.safe_load(text)

    # -------------------------------------------------------------
    # Document Recognition
    # -------------------------------------------------------------

    @staticmethod
    def _looks_like_openapi(
        document: Dict[str, Any],
    ) -> bool:
        """
        Quick structural validation.

        A valid specification must contain

        OpenAPI 3

            openapi

        or

        Swagger 2

            swagger
        """

        if not isinstance(document, dict):

            return False

        if "openapi" in document:

            return True

        if "swagger" in document:

            return True

        return False

    # -------------------------------------------------------------
    # Specification Validation
    # -------------------------------------------------------------

    def _validate_document(
        self,
        document: Dict[str, Any],
    ) -> None:
        """
        Validate specification version compatibility.

        Supported

        OpenAPI

            3.0.x
            3.1.x

        Swagger

            2.0
        """

        logger.info("Validating specification...")

        if "openapi" in document:

            version = str(document["openapi"])

            if not version.startswith(SUPPORTED_OPENAPI_VERSIONS):

                raise UnsupportedSpecification(
                    f"Unsupported OpenAPI version: {version}"
                )

            logger.info("Detected OpenAPI %s", version)

            return

        if "swagger" in document:

            version = str(document["swagger"])

            if version != SUPPORTED_SWAGGER_VERSION:

                raise UnsupportedSpecification(
                    f"Unsupported Swagger version: {version}"
                )

            logger.info("Detected Swagger %s", version)

            return

        raise InvalidSpecification(
            "Document is not a valid OpenAPI/Swagger specification."
        )
    # -------------------------------------------------------------
    # Specification Parsing
    # -------------------------------------------------------------

    def _parse_specification(
        self,
        raw_document: Dict[str, Any],
        specification_url: str,
    ) -> APISpecification:
        """
        Convert an OpenAPI/Swagger document into the
        normalized APISpecification model used by the
        rest of API Sentinel AI.

        Parameters
        ----------
        raw_document:
            Raw OpenAPI / Swagger document.

        specification_url:
            URL from which the specification was downloaded.

        Returns
        -------
        APISpecification
        """

        logger.info("Parsing specification...")
        self._cached_document = raw_document

        info = raw_document.get("info", {})

        title = info.get("title", "Unknown API")

        version = info.get("version", "Unknown")

        specification_version = (
            raw_document.get("openapi")
            or raw_document.get("swagger")
            or "Unknown"
        )

        base_url = self._extract_base_url(
            raw_document,
            specification_url,
        )

        api_spec = APISpecification(
            title=title,
            version=version,
            specification_version=specification_version,
            base_url=base_url,
            raw_document=raw_document,
        )

        paths = raw_document.get("paths", {})

        logger.info(
            "Discovered %d API paths.",
            len(paths),
        )

        for path, operations in paths.items():

            self._parse_path_item(
                api_spec,
                path,
                operations,
            )

        logger.info(
            "Parsed %d endpoints.",
            len(api_spec.endpoints),
        )

        return api_spec

    # -------------------------------------------------------------
    # Base URL Extraction
    # -------------------------------------------------------------

    def _extract_base_url(
        self,
        document: Dict[str, Any],
        specification_url: str,
    ) -> str:
        """
        Extract the base URL for the API.

        Supports both

        OpenAPI 3

            servers[]

        and

        Swagger 2

            host
            basePath
            schemes
        """

        if "servers" in document:

            servers = document.get("servers", [])

            if servers:

                return servers[0].get(
                    "url",
                    self.base_url,
                )

        if "host" in document:

            scheme = "https"

            schemes = document.get(
                "schemes",
                [],
            )

            if schemes:

                scheme = schemes[0]

            host = document.get("host", "")

            base_path = document.get(
                "basePath",
                "",
            )

            return (
                f"{scheme}://{host}{base_path}"
            )

        return self.base_url

    # -------------------------------------------------------------
    # Parse Path Item
    # -------------------------------------------------------------

    def _parse_path_item(
        self,
        api_spec: APISpecification,
        path: str,
        operations: Dict[str, Any],
    ) -> None:
        """
        Parse every HTTP method available
        under a path.

        Example

            /users

                GET

                POST

                DELETE
        """

        valid_methods = {
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "head",
            "options",
        }

        for method, operation in operations.items():

            if method.lower() not in valid_methods:

                continue

            endpoint = self._create_endpoint(
                path,
                method,
                operation,
            )

            api_spec.endpoints.append(endpoint)

    # -------------------------------------------------------------
    # Endpoint Creation
    # -------------------------------------------------------------

    def _create_endpoint(
        self,
        path: str,
        method: str,
        operation: Dict[str, Any],
    ) -> EndpointInfo:
        """
        Convert one OpenAPI operation into
        an EndpointInfo object.
        """

        return EndpointInfo(
            path=path,
            method=method.upper(),
            operation_id=operation.get(
                "operationId"
            ),
            summary=operation.get(
                "summary"
            ),
            description=operation.get(
                "description"
            ),
            tags=operation.get(
                "tags",
                [],
            ),
            parameters=self._extract_parameters(
                operation,
            ),
            request_body=self._extract_request_body(
                operation,
            ),
            responses=operation.get(
                "responses",
                {},
            ),
            security=operation.get(
                "security",
                [],
            ),
            deprecated=operation.get(
                "deprecated",
                False,
            ),
        )
    # -------------------------------------------------------------
    # Parameter Extraction
    # -------------------------------------------------------------

    def _extract_parameters(
        self,
        operation: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Extract all operation parameters into a
        normalized representation.

        Supported locations

        - query
        - path
        - header
        - cookie
        """

        parameters: List[Dict[str, Any]] = []

        for parameter in operation.get("parameters", []):

            parameter = self._resolve_reference(parameter)

            schema = parameter.get("schema", {})

            parameters.append(
                {
                    "name": parameter.get("name"),
                    "location": parameter.get("in"),
                    "required": parameter.get(
                        "required",
                        False,
                    ),
                    "description": parameter.get(
                        "description",
                        "",
                    ),
                    "type": schema.get(
                        "type",
                        "unknown",
                    ),
                    "format": schema.get(
                        "format",
                    ),
                    "enum": schema.get(
                        "enum",
                        [],
                    ),
                    "default": schema.get(
                        "default",
                    ),
                }
            )

        return parameters

    # -------------------------------------------------------------
    # Request Body Extraction
    # -------------------------------------------------------------

    def _extract_request_body(
        self,
        operation: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Normalize request body information.

        Supports

        OpenAPI 3.x

            requestBody

        Swagger 2.0

            body parameters
        """

        if "requestBody" in operation:

            body = self._resolve_reference(
                operation["requestBody"]
            )

            content = body.get("content", {})

            parsed_content = {}

            for media_type, media in content.items():

                schema = media.get("schema", {})

                parsed_content[media_type] = (
                    self._extract_schema(schema)
                )

            return {
                "required": body.get(
                    "required",
                    False,
                ),
                "content": parsed_content,
            }

        #
        # Swagger 2.0
        #

        for parameter in operation.get(
            "parameters",
            [],
        ):

            parameter = self._resolve_reference(
                parameter
            )

            if parameter.get("in") != "body":

                continue

            return {
                "required": parameter.get(
                    "required",
                    False,
                ),
                "content": {
                    "application/json":
                        self._extract_schema(
                            parameter.get(
                                "schema",
                                {},
                            )
                        )
                },
            }

        return {}

    # -------------------------------------------------------------
    # Schema Extraction
    # -------------------------------------------------------------

    def _extract_schema(
        self,
        schema: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Convert an OpenAPI schema into a
        simplified recursive representation.

        Handles

        - primitive types
        - objects
        - arrays
        - references
        """

        schema = self._resolve_reference(schema)

        if not schema:

            return {}

        schema_type = schema.get(
            "type",
            "object",
        )

        #
        # Object
        #

        if schema_type == "object":

            properties = {}

            for name, value in schema.get(
                "properties",
                {},
            ).items():

                properties[name] = (
                    self._extract_schema(value)
                )

            return {
                "type": "object",
                "required": schema.get(
                    "required",
                    [],
                ),
                "properties": properties,
            }

        #
        # Array
        #

        if schema_type == "array":

            return {
                "type": "array",
                "items": self._extract_schema(
                    schema.get("items", {})
                ),
            }

        #
        # Primitive
        #

        return {
            "type": schema.get("type"),
            "format": schema.get("format"),
            "enum": schema.get(
                "enum",
                [],
            ),
            "default": schema.get(
                "default",
            ),
            "example": schema.get(
                "example",
            ),
        }

    # -------------------------------------------------------------
    # Reference Resolver
    # -------------------------------------------------------------

    def _resolve_reference(
        self,
        node: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Resolve local OpenAPI references.

        Example

        $ref

            #/components/schemas/User

        This keeps every downstream module
        independent from OpenAPI internals.
        """

        if "$ref" not in node:

            return node

        reference = node["$ref"]

        if not reference.startswith("#/"):

            logger.warning(
                "External reference skipped: %s",
                reference,
            )

            return {}

        current = self._cached_document

        for part in reference.lstrip("#/").split("/"):

            current = current.get(part)

            if current is None:

                logger.warning(
                    "Unable to resolve %s",
                    reference,
                )

                return {}

        if isinstance(current, dict):

            return current

        return {}

    # -------------------------------------------------------------
    # Cached Specification
    # -------------------------------------------------------------

    @property
    def _cached_document(self) -> Dict[str, Any]:
        """
        Cached OpenAPI document.

        This property is intentionally isolated
        because future versions of API Sentinel
        may cache specifications in Redis,
        SQLite, or disk without changing the
        parser implementation.
        """

        if not hasattr(self, "__cached_document"):

            raise RuntimeError(
                "Specification cache has not "
                "been initialized."
            )

        return self.__cached_document

    @_cached_document.setter
    def _cached_document(
        self,
        value: Dict[str, Any],
    ) -> None:

        self.__cached_document = value
    # -------------------------------------------------------------
    # Discovery Summary
    # -------------------------------------------------------------

    def generate_summary(
        self,
        specification: APISpecification,
    ) -> Dict[str, Any]:
        """
        Generate a high-level summary of the discovered API.

        This summary is displayed in the dashboard and later
        included in the professional security report.
        """

        methods: Dict[str, int] = {}
        tags: Dict[str, int] = {}
        secured = 0

        for endpoint in specification.endpoints:

            methods[endpoint.method] = (
                methods.get(endpoint.method, 0) + 1
            )

            if endpoint.security:
                secured += 1

            for tag in endpoint.tags:
                tags[tag] = tags.get(tag, 0) + 1

        return {
            "api_title": specification.title,
            "api_version": specification.version,
            "specification_version": specification.specification_version,
            "base_url": specification.base_url,
            "total_endpoints": len(specification.endpoints),
            "secured_endpoints": secured,
            "public_endpoints": len(specification.endpoints) - secured,
            "methods": methods,
            "tags": tags,
        }

    # -------------------------------------------------------------
    # Endpoint Serialization
    # -------------------------------------------------------------

    def endpoint_to_dict(
        self,
        endpoint: EndpointInfo,
    ) -> Dict[str, Any]:
        """
        Convert EndpointInfo into a JSON-serializable dictionary.
        """

        return {
            "path": endpoint.path,
            "method": endpoint.method,
            "operation_id": endpoint.operation_id,
            "summary": endpoint.summary,
            "description": endpoint.description,
            "tags": endpoint.tags,
            "parameters": endpoint.parameters,
            "request_body": endpoint.request_body,
            "responses": endpoint.responses,
            "security": endpoint.security,
            "deprecated": endpoint.deprecated,
        }

    # -------------------------------------------------------------
    # Specification Serialization
    # -------------------------------------------------------------

    def specification_to_dict(
        self,
        specification: APISpecification,
    ) -> Dict[str, Any]:
        """
        Convert APISpecification into a JSON-serializable object.
        """

        return {
            "title": specification.title,
            "version": specification.version,
            "specification_version": specification.specification_version,
            "base_url": specification.base_url,
            "endpoints": [
                self.endpoint_to_dict(endpoint)
                for endpoint in specification.endpoints
            ],
        }

    # -------------------------------------------------------------
    # Export Specification
    # -------------------------------------------------------------

    def export_inventory(
        self,
        specification: APISpecification,
        output_path: str,
    ) -> pathlib.Path:
        """
        Export the discovered endpoint inventory as JSON.

        Parameters
        ----------
        specification:
            Parsed API specification.

        output_path:
            Destination JSON file.
        """

        destination = pathlib.Path(output_path)

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with destination.open(
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                self.specification_to_dict(specification),
                file,
                indent=4,
                ensure_ascii=False,
            )

        logger.info(
            "Endpoint inventory exported to %s",
            destination,
        )

        return destination

    # -------------------------------------------------------------
    # Export Discovery Summary
    # -------------------------------------------------------------

    def export_summary(
        self,
        specification: APISpecification,
        output_path: str,
    ) -> pathlib.Path:
        """
        Export the discovery summary as JSON.
        """

        destination = pathlib.Path(output_path)

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        summary = self.generate_summary(specification)

        with destination.open(
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                summary,
                file,
                indent=4,
                ensure_ascii=False,
            )

        logger.info(
            "Discovery summary exported to %s",
            destination,
        )

        return destination

    # -------------------------------------------------------------
    # Convenience Method
    # -------------------------------------------------------------

    def discover_and_export(
        self,
        inventory_output: str,
        summary_output: str,
    ) -> APISpecification:
        """
        Complete discovery workflow.

        1. Discover API
        2. Parse specification
        3. Export inventory
        4. Export summary

        Returns
        -------
        APISpecification
        """

        specification = self.discover()

        self.export_inventory(
            specification,
            inventory_output,
        )

        self.export_summary(
            specification,
            summary_output,
        )

        return specification