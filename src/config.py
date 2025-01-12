import os

capi_version: str = "2.11.3"
enforcement_hash: str = "507409183b9903b911945fa68e24c1d9"

proxy: str = os.getenv("PROXY_URL", None)

use_real_bda: bool = os.getenv("USE_REAL_BDA", False)
xevil_updated: bool = os.getenv("XEVIL_UPDATED", True)
