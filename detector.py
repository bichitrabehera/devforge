"""Backwards-compatibility shim (older code imported these names)."""

from src.detector import (ALERT_LABELS, SERVICE_GRAPH, SUPPORTED_OFFSET_MS,
                          REORDER_TOLERANCE_S, evaluate_labelled,
                          evaluate_live)  # noqa: F401
