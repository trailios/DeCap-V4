import os

capi_version: str = "2.12.9"
enforcement_hash: str = "0a3d1c68c34cf87e8eedcc692165053d"

proxy: str = os.getenv("PROXY_URL", None)

use_real_bda: bool = os.getenv("USE_REAL_BDA", False)
xevil_updated: bool = os.getenv("XEVIL_UPDATED", True)
