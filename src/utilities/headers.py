import random, string, json
from typing import Dict, Optional, List, Tuple

# this is fucking shit dont mind it

class Headers:
    """
    An enhanced class to generate HTTP headers with customizable fields and
    randomization for specific values like User-Agent and Accept-Language.
    """

    def __init__(
        self,
        browser: Optional[str] = None,
        version: Optional[str] = None,
        os: Optional[str] = None,
        accept: str = "*/*",
        accept_encoding: str = "gzip, deflate, br",
        accept_language: Optional[str] = None,
        sec_ch_ua: Optional[str] = None,
        sec_ch_ua_platform: Optional[str] = None,
        sec_fetch_dest: str = "empty",
        sec_fetch_mode: str = "cors",
        sec_fetch_site: str = "same-origin",
        upgrade_insecure_requests: Optional[str] = None,
        user_agent: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        Initializes header attributes, with improvements for realism and evasion.
        """
        self.browser, self.version, self.os = (
            self._choose_browser_os_version()
            if browser and version and os is None
            else (browser, version, os)
        )
        self.user_agent: str = user_agent or self._choose_user_agent()
        self.accept: str = accept
        self.accept_encoding: str = accept_encoding
        self.accept_language: str = accept_language or self._generate_accept_language()
        self.sec_ch_ua: str = sec_ch_ua or self._choose_sec_ch_ua()
        self.sec_ch_ua_mobile: str = "0?"
        self.sec_ch_ua_platform: str = (
            sec_ch_ua_platform or self._choose_sec_ch_ua_platform()
        )
        self.sec_fetch_dest: str = sec_fetch_dest
        self.sec_fetch_mode: str = sec_fetch_mode
        self.sec_fetch_site: str = sec_fetch_site
        self.upgrade_insecure_requests: Optional[str] = (
            upgrade_insecure_requests if random.uniform(0, 0.81) > 0.8 else None
        )
        self.custom_headers: Dict[str, str] = custom_headers or {}

    def headers(self) -> Dict[str, str]:
        """
        Returns a dictionary of HTTP headers.
        """
        headers: Dict[str, str] = {
            "Accept": self.accept,
            "Accept-Encoding": self.accept_encoding,
            "Accept-Language": self.accept_language,
            "Sec-Ch-Ua-Mobile": self.sec_ch_ua_mobile,
            "Sec-Ch-Ua-Platform": self.sec_ch_ua_platform,
            "Sec-Fetch-Dest": self.sec_fetch_dest,
            "Sec-Fetch-Mode": self.sec_fetch_mode,
            "Sec-Fetch-Site": self.sec_fetch_site,
            "User-Agent": self.user_agent,
        }
        if "firefox" in self.user_agent.lower():
            headers["TE"] = "trailers"
        if self.sec_ch_ua:
            headers["Sec-Ch-Ua"] = self.sec_ch_ua
        if self.upgrade_insecure_requests:
            headers["Upgrade-Insecure-Requests"] = self.upgrade_insecure_requests

        headers.update(self.custom_headers)

        return headers

    def update(self, headers: str) -> None:
        """
        Updates header attributes based on the input string representation of a dictionary.
        """
        try:
            headers_dict: Dict[str, str] = json.loads(headers)
            for key, value in headers_dict.items():
                setattr(self, key.lower().replace("-", "_"), value)
            self.custom_headers.update(
                {k: v for k, v in headers_dict.items() if k not in self.__dict__}
            )
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid header format: {e}")

    def _choose_browser_os_version(self) -> Tuple[str, int, str]:
        """
        Randomly choose a browser, version, and OS for more realistic User-Agent strings.
        """
        browsers: List[Tuple[str, int, str]] = [
            ("chrome", random.randint(129, 131), "Windows NT 10.0; Win64; x64"),
            ("opera", random.randint(129, 131), "Windows NT 10.0; Win64; x64"),
            ("edge", random.randint(129, 131), "Windows NT 10.0; Win64; x64"),
            ("firefox", random.randint(130, 132), "Windows NT 10.0; Win64; x64"),
            (
                "chrome mac",
                random.randint(129, 131),
                "Macintosh; Intel Mac OS X 14_7_1",
            ),
            (
                "firefox mac",
                random.randint(130, 132),
                "Macintosh; Intel Mac OS X 14_7_1",
            ),
            ("chrome linux", random.randint(129, 131), "Linux x86_64"),
            ("firefox linux", random.randint(130, 132), "Linux x86_64"),
            ("safari", 18.0, "Macintosh; Intel Mac OS X 14_7_1"),
        ]
        return random.choice(browsers)

    def _choose_user_agent(self) -> str:
        """
        Generates a User-Agent string based on the randomly selected browser and OS.
        """
        if (
            self.browser == "chrome"
            or self.browser == "chrome mac"
            or self.browser == "chrome linux"
        ):
            return f"Mozilla/5.0 ({self.os}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{self.version}.0.0.0 Safari/537.36"
        elif self.browser == "edge":
            return f"Mozilla/5.0 ({self.os}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{self.version}.0.0.0 Safari/537.36 Edg/{self.version}.0.0.0"
        elif (
            self.browser == "firefox"
            or self.browser == "firefox mac"
            or self.browser == "firefox linux"
        ):
            return f"Mozilla/5.0 ({self.os}; rv:{self.version}.0) Gecko/20100101 Firefox/{self.version}.0"
        elif self.browser == "safari":
            return f"Mozilla/5.0 ({self.os}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{self.version} Safari/605.1.15"
        elif self.browser == "opera":
            return f"Mozilla/5.0 ({self.os}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{self.version}.0.0.0 Safari/537.36 OPR/114.0.5282.93"

    def _choose_sec_ch_ua(self) -> str:
        """
        Generates the Sec-CH-UA header based on the User-Agent.
        """

        if "Edg" in self.user_agent:
            return f'"Chromium";v="{self.version}", "Microsoft Edge";v="{self.version}", "Not;A=Brand";v="99"' # idfk the not a abrand version
        elif "Chrome" in self.user_agent:
            return f'"Chromium";v="{self.version}", "Google Chrome";v="{self.version}", "Not;A=Brand";v="99"'
        elif "Firefox" in self.user_agent:
            return None
        elif "Safari" in self.user_agent:
            return None
        elif "opr" in self.user_agent.lower():
            return f'"Chromium";v="{self.version}", "Opera GX";v="{self.version}", "Not;A=Brand";v="24"'
        else:
            return f'"Chromium";v="{self.version}", "Not;A=Brand";v="99"'

    def _choose_sec_ch_ua_platform(self) -> str:
        """
        Choose a platform that matches the selected operating system.
        """
        if "Macintosh" in self.os:
            return '"macOS"'
        elif "Windows" in self.os:
            return '"Windows"'
        elif "Linux" in self.os:
            return '"Linux"'
        return '"Unknown"'

    def _generate_accept_language(self, max_lang: int = random.randint(0, 3)) -> str:
        """
        Generates the Accept-Language header mimicking real-world browser behavior.
        """
        languages = [
            "en-US",
            "en-GB",
            "es-ES",
            "fr-FR",
            "de-DE",
            "zh-CN",
            "ja-JP",
            "ru-RU",
            "pt-BR",
            "it-IT",
            "ko-KR",
            "ar-SA",
            "nl-NL",
            "tr-TR",
            "pl-PL",
            "id-ID",
            "th-TH",
            "sv-SE",
            "fi-FI",
            "da-DK",
            "no-NO",
            "el-GR",
            "he-IL",
            "vi-VN",
            "hi-IN",
        ]

        base_lang = random.choice(["en-US", "en-GB", "fr-FR", "de-DE", "es-ES"])
        shuffled_langs = random.sample(languages, k=max_lang)
        chosen_langs = [base_lang] + shuffled_langs

        q_values = [round(0.9 - 0.1 * i, 1) for i in range(len(chosen_langs))]
        lang_with_q = [f"{lang};q={q}" for lang, q in zip(chosen_langs, q_values)]

        if "-" in base_lang:
            base_lang_code = base_lang.split("-")[0]
            lang_with_q[0] = f"{base_lang},{base_lang_code};q={q_values[0]}"

        return ",".join(lang_with_q)

    def to_json(self) -> str:
        """
        Returns a JSON string representation of the headers.
        """
        return json.dumps(self.headers(), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "Headers":
        """
        Creates a Headers instance from a JSON string.
        """
        data = json.loads(json_str)
        headers = cls()
        headers.update(json.dumps(data))
        return headers

    def randomize(self) -> None:
        """
        Randomizes all header values.
        """
        self.__init__()


if __name__ == "__main__":
    headers = Headers()
    print(headers.to_json())
