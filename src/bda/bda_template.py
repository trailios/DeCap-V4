from src.config import capi_version, enforcement_hash
from typing import Optional, Dict, Any
import hashlib


class FunCaptchaSession:
    def __init__(
        self,
        public_key: Optional[str] = None,
        service_url: Optional[str] = None,
        site_url: Optional[str] = None,
        capi_mode: str = "lightbox",
        method: Optional[str] = None,
        blob: Optional[str] = None,
    ):
        self.method: Optional[str] = method
        self.public_key: Optional[str] = public_key
        self.service_url: Optional[str] = service_url
        self.site_url: Optional[str] = site_url
        self.capi_mode: str = capi_mode
        self.blob: Optional[str] = blob

        if method:
            self.get_method()

    def get_method(self) -> None:
        if self.method == "outlook":
            self.public_key = "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA"
            self.service_url = "https://client-api.arkoselabs.com"
            self.site_url = "https://iframe.arkoselabs.com"
            self.capi_mode = "inline"
            self.language = "en"
        elif self.method == "twitter":
            self.public_key = "2CB16598-CB82-4CF7-B332-5990DB66F3AB"
            self.service_url = "https://client-api.arkoselabs.com"
            self.site_url = "https://iframe.arkoselabs.com"
            self.capi_mode = "inline"
            self.language = None
        elif self.method == "twitter_unlock":
            self.public_key = "0152B4EB-D2DC-460A-89A1-629838B529C9"
            self.service_url = "https://client-api.arkoselabs.com"
            self.site_url = "https://iframe.arkoselabs.com"
            self.capi_mode = "inline"
            self.language = None
        elif self.method == "roblox_signup":
            self.public_key = "A2A14B1D-1AF3-C791-9BBC-EE33CC7A0A6F"
            self.service_url = "https://arkoselabs.roblox.com"
            self.site_url = "https://www.roblox.com"
            self.capi_mode = "inline"
            self.language = None
        elif self.method == "roblox_login":
            self.public_key = "476068BF-9607-4799-B53D-966BE98E2B81"
            self.service_url = "https://arkoselabs.roblox.com"
            self.site_url = "https://www.roblox.com"
            self.capi_mode = "inline"
            self.language = None
        elif self.method == "roblox_join":
            self.public_key = "63E4117F-E727-42B4-6DAA-C8448E9B137F"
            self.service_url = "https://arkoselabs.roblox.com"
            self.site_url = "https://www.roblox.com"
            self.capi_mode = "inline"
            self.language = None
        elif self.method == "ea":
            self.public_key = "73BEC076-3E53-30F5-B1EB-84F494D43DBA"
            self.service_url = "https://ea-api.arkoselabs.com"
            self.site_url = "https://signin.ea.com"
            self.capi_mode = "lightbox"
            self.language = None
        elif self.method == "github-signup":
            self.public_key = "747B83EC-2CA3-43AD-A7DF-701F286FBABA"
            self.service_url = "https://github-api.arkoselabs.com"
            self.site_url = "https://octocaptcha.com"
            self.capi_mode = "inline"
            self.language = None
        elif self.method == "demo":
            self.public_key = "DF9C4D87-CB7B-4062-9FEB-BADB6ADA61E6"
            self.service_url = "https://client-api.arkoselabs.com"
            self.site_url = "https://demo.arkoselabs.com"
            self.capi_mode = "inline"
            self.language = "en"
        elif self.method == "roblox_wall":
            self.public_key = "63E4117F-E727-42B4-6DAA-C8448E9B137F"
            self.service_url = "https://arkoselabs.roblox.com"
            self.site_url = "https://www.roblox.com"
            self.capi_mode = "inline"
            self.language = None
        elif self.method == "airbnb-register":
            self.public_key = "2F0D6CB5-ACAC-4EA9-9B2A-A5F90A2DF15E"
            self.service_url = "https://airbnb-api.arkoselabs.com"
            self.site_url = "https://www.airbnb.com"
            self.capi_mode = "inline"
            self.language = "en"
        else:
            raise Exception("Invalid method")


class FunCaptchaOptions:
    def __init__(
        self,
        options: Optional[Dict[str, Any]] = None,
        method: Optional[str] = None,
        useragent: Optional[str] = None,
    ):
        self.method: Optional[str] = method
        self.options: Optional[Dict[str, Any]] = options
        self.hashing = lambda data: hashlib.md5(
            data.encode() if isinstance(data, str) else data
        ).hexdigest()

        if method:
            self.get_options()
            if useragent:
                if "firefox" in useragent:
                    self.options["window__ancestor_origins"] = "null"

    def get_options(self) -> None:
        if self.method == "outlook":
            self.options = {
                "document__referrer": "https://iframe.arkoselabs.com/",
                "window__ancestor_origins": [
                    "https://iframe.arkoselabs.com",
                    "https://signup.live.com",
                ],
                "window__tree_index": [1, 0],
                "window__tree_structure": "[[[]],[[]]]",
                "window__location_href": f"https://client-api.arkoselabs.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": f"https://iframe.arkoselabs.com/B7D8911C-5CC8-A9A3-35B0-554ACEE604DA/index.html",
                "client_config__language": "en",
                "client_config__surl": "https://client-api.arkoselabs.com",
                "c8480e29a": str(self.hashing("https://client-api.arkoselabs.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "twitter":
            self.options = {
                "document__referrer": "https://iframe.arkoselabs.com/",
                "window__ancestor_origins": [
                    "https://iframe.arkoselabs.com",
                    "https://twitter.com",
                ],
                "window__tree_index": [0, 0],
                "window__tree_structure": "[[[]]]",
                "window__location_href": f"https://client-api.arkoselabs.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": "https://iframe.arkoselabs.com/2CB16598-CB82-4CF7-B332-5990DB66F3AB/index.html",
                "client_config__language": None,
                "client_config__surl": "https://client-api.arkoselabs.com",
                "c8480e29a": str(self.hashing("https://client-api.arkoselabs.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "twitter_unlock":
            self.options = {
                "document__referrer": "https://iframe.arkoselabs.com/",
                "window__ancestor_origins": [
                    "https://iframe.arkoselabs.com",
                    "https://twitter.com",
                ],
                "window__tree_index": [0, 0],
                "window__tree_structure": "[[[]]]",
                "window__location_href": f"https://client-api.arkoselabs.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": "https://iframe.arkoselabs.com/0152B4EB-D2DC-460A-89A1-629838B529C9/index.html",
                "client_config__language": None,
                "client_config__surl": "https://client-api.arkoselabs.com",
                "c8480e29a": str(self.hashing("https://client-api.arkoselabs.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "roblox_signup":
            self.options = {
                "document__referrer": "https://www.roblox.com/",
                "window__ancestor_origins": [
                    "https://www.roblox.com",
                    "https://www.roblox.com",
                ],
                "window__tree_index": [1, 0],
                "window__tree_structure": "[[],[[]]]",
                "window__location_href": f"https://arkoselabs.roblox.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": f"https://www.roblox.com/de/arkose/iframe",
                "client_config__language": None,
                "client_config__surl": "https://arkoselabs.roblox.com",
                "c8480e29a": str(self.hashing("https://arkoselabs.roblox.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "roblox_login":
            self.options = {
                "document__referrer": "https://www.roblox.com/",
                "window__ancestor_origins": [
                    "https://www.roblox.com",
                    "https://www.roblox.com",
                ],
                "window__tree_index": [1, 0],
                "window__tree_structure": "[[],[[]]]",
                "window__location_href": f"https://arkoselabs.roblox.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": "https://www.roblox.com/de/arkose/iframe",
                "client_config__language": None,
                "client_config__surl": "https://arkoselabs.roblox.com",
                "c8480e29a": str(self.hashing("https://arkoselabs.roblox.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "roblox_join" or self.method == "roblox_follow":
            self.options = {
                "document__referrer": "https://www.roblox.com/",
                "window__ancestor_origins": [
                    "https://www.roblox.com",
                    "https://www.roblox.com",
                ],
                "window__tree_index": [1, 0],
                "window__tree_structure": "[[],[[]]]",
                "window__location_href": f"https://arkoselabs.roblox.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": "https://www.roblox.com/de/arkose/iframe",
                "client_config__language": None,
                "client_config__surl": "https://arkoselabs.roblox.com",
                "c8480e29a": str(self.hashing("https://arkoselabs.roblox.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "ea":
            self.options = {
                "document__referrer": "https://signin.ea.com/",
                "window__ancestor_origins": [
                    "https://signin.ea.com",
                ],
                "window__tree_index": [0],
                "window__tree_structure": "[[]]",
                "window__location_href": f"https://ea-api.arkoselabs.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": "https://signin.ea.com/p/juno/create",
                "client_config__language": "en",
                "client_config__surl": "https://ea-api.arkoselabs.com",
                "c8480e29a": str(self.hashing("https://ea-api.arkoselabs.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "github-signup":
            self.options = {
                "document__referrer": "https://octocaptcha.com/",
                "window__ancestor_origins": [
                    "https://octocaptcha.com",
                    "https://github.com",
                ],
                "window__tree_index": [0, 0],
                "window__tree_structure": "[[[]],[]]",
                "window__location_href": f"https://github-api.arkoselabs.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": "https://octocaptcha.com/",
                "client_config__language": None,
                "client_config__surl": "https://github-api.arkoselabs.com",
                "c8480e29a": str(self.hashing("https://github-api.arkoselabs.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "demo":
            self.options = {
                "document__referrer": "https://login.microsoftonline.com/",
                "window__ancestor_origins": [
                    "https://demo.arkoselabs.com",
                ],
                "window__tree_index": [0],
                "window__tree_structure": "[[]]",
                "window__location_href": f"https://cleint-api.arkoselabs.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": "https://demo.arkoselabs.com/",
                "client_config__language": "en",
                "client_config__surl": "https://demo-api.arkoselabs.com",
                "c8480e29a": str(self.hashing("https://client-api.arkoselabs.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "roblox_wall":
            self.options = {
                "document__referrer": "https://www.roblox.com/",
                "window__ancestor_origins": [
                    "https://www.roblox.com",
                    "https://www.roblox.com",
                ],
                "window__tree_index": [1, 0],
                "window__tree_structure": "[[],[[]]]",
                "window__location_href": f"https://arkoselabs.roblox.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": "https://www.roblox.com/de/arkose/iframe",
                "client_config__language": None,
                "client_config__surl": "https://arkoselabs.roblox.com",
                "c8480e29a": str(self.hashing("https://arkoselabs.roblox.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "airbnb-register":
            self.options = {
                "document__referrer": "https://www.airbnb.com/",
                "window__ancestor_origins": [
                    "https://www.airbnb.com",
                ],
                "window__tree_index": [1],
                "window__tree_structure": "[[[]],[]]",
                "window__location_href": f"https://airbnb-api.arkoselabs.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": "https://www.airbnb.com/",
                "client_config__language": "en",
                "client_config__surl": "https://airbnb-api.arkoselabs.com",
                "c8480e29a": str(self.hashing("https://airbnb-api.arkoselabs.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        else:
            raise Exception("Invalid method")
