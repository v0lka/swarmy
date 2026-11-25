"""Platform HTTP path: the only network route, guarded by pipeline and limits (arch §6.2).

``swarmy.tools.http`` carries the execution perimeter of arch §6.2:

* :mod:`models` — ``RequestSpec`` / ``ResponseRecord`` (the pipeline's
  boundary types);
* :mod:`client` — ``SwarmyHttpClient``, the guardrails → limiter → manual
  redirects → evidence → projection pipeline every call runs through;
* :mod:`tools` — the four platform tools ``http_get``/``http_post``/
  ``http_put``/``http_delete`` (thin wrappers, AD-7 risk classes);
* :mod:`evidence` — ``EvidenceRecorder`` (raw session evidence files +
  ``Evidence`` pointer rows, D20/D21).

Import boundary (arch §2.5): this package uses guardrails *models*, events
*models* and its ``tools`` siblings — never ``swarmy.core`` and never the L0
harness directly.
"""

from swarmy.tools.http.client import (
    HttpClientEvents,
    OutboundSecretWarn,
    SwarmyHttpClient,
)
from swarmy.tools.http.evidence import EvidenceRecorder
from swarmy.tools.http.models import HttpMethod, RequestSpec, ResponseRecord
from swarmy.tools.http.tools import make_http_tools, register_http_tools

__all__ = [
    "EvidenceRecorder",
    "HttpClientEvents",
    "HttpMethod",
    "OutboundSecretWarn",
    "RequestSpec",
    "ResponseRecord",
    "SwarmyHttpClient",
    "make_http_tools",
    "register_http_tools",
]
