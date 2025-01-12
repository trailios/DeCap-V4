import json, random
import string, time

from typing import Dict, Optional, Tuple, Any
from urllib.parse import urlencode
from hashlib import sha512


from curl_cffi import requests
from src.arkose_session.crypto import aes_encrypt
from src.bda.fingerprint import generate_browser_data
from src.arkose_session.game import Game
from src.utilities.headers import Headers
from src.utilities.format import construct_form_data
from src.config import capi_version, enforcement_hash

enforcement_url = f"/v2/{capi_version}/enforcement.{enforcement_hash}.html"

def sort_headers(headers: Dict[str, str]) -> Dict[str, str]:
    header_order = [
        "Host",
        "Connection",
        "sec-ch-ua-platform",
        "x-ark-esync-value",
        "User-Agent",
        "sec-ch-ua",
        "Content-Type",
        "sec-ch-ua-mobile",
        "X-NewRelic-Timestamp",
        "X-Requested-ID",
        "X-Requested-With",
        "Accept",
        "Origin",
        "Sec-Fetch-Site",
        "Sec-Fetch-Mode",
        "Sec-Fetch-Dest",
        "Referer",
        "Accept-Encoding",
        "Accept-Language",
        "Cookie",
        "Content-Length"
    ]

    return {k: v for k, v in sorted(headers.items(), key=lambda item: header_order.index(item[0]) if item[0] in header_order else len(header_order))}

class ChallengeSession:
    """
    Challenge Session
    """

    def __init__(
        self,
        captcha_session,
        proxy: Optional[str] = None,
        browser_data: Optional[Tuple[str, str, str, str, str]] = None,
        timeout: int = 30,
    ):
        self.captcha_session = captcha_session

        self.headers = Headers(
            browser=browser_data[0],
            version=browser_data[1],
            os=browser_data[2],
            accept_language=browser_data[3],
        )
        self.cookies = browser_data[4]

        self.session = requests.Session()
        self.session.default_headers = 0
        self.session.impersonate = random.choice(["chrome131", "safari18_0", "safari18_0_ios", "chrome131_android"])
        self.session.timeout = timeout
        self.proxy = "http://" + proxy if "http://" not in proxy else proxy
        self.session.proxies = {"http": self.proxy, "https": self.proxy}

        self.browser_data: Optional[str] = None
        self.detailed_browser_data: Optional[str] = None
        self.proxy: str = proxy

        self.arkose_token: Optional[str] = None
        self.session_token: Optional[str] = None
        self.session_id: Optional[str] = None
        self.analytics_tier: Optional[str] = None
        self.security_score: Optional[int] = None
        self.encrypted_mode: Optional[bool] = None

    def _get_timestamp(self) -> Tuple[str, str]:
        """
        Generates a timestamp string from the current time and returns it as a cookie.

        Returns:
            Tuple[str, str]: A tuple containing the cookie string and the value.
        """
        timestamp_str = str(int(time.time() * 1000))
        value = f"{timestamp_str[:7]}00{timestamp_str[7:]}"
        cookie = f"timestamp={value}"
        return cookie, value

    def _generate_challenge_task(self) -> Dict[str, Any]:
        """
        Generates a dictionary containing the Arkose Labs challenge task details.

        Returns:
            Dict[str, Any]: A dictionary containing the challenge task details.
        """
        (
            self.browser_data,  # noqa: F841
            self.headers.ua,  # noqa: F841
            self.detailed_browser_data,  # noqa: F841
            additional_headers,
        ) = generate_browser_data(
            self.headers,
            method=self.captcha_session.method,
            proxy=self.proxy,
        )
        if additional_headers:
            self.headers.update(additional_headers)

        task = {
            "bda": self.browser_data,
            "public_key": self.captcha_session.public_key,
            "site": self.captcha_session.site_url,
            "userbrowser": self.headers.ua,
            "capi_version": capi_version,
            "capi_mode": self.captcha_session.capi_mode,
            "style_theme": "default",
            "rnd": random.random(),
        }
        if self.captcha_session.language:
            task["language"] = self.captcha_session.language
        if self.captcha_session.blob:
            task["data[blob]"] = self.captcha_session.blob
        if self.captcha_session.method == "github-signup":
            task["data[origin_page]"] = "github_signup_redesign"
        return task

    def fetch_challenge_token(self) -> str:
        """
        Fetches an Arkose Labs challenge token.

        Returns:
            str: The Arkose Labs challenge token.
        """
        task = self._generate_challenge_task()
        cookie, timestamp_value = self._get_timestamp()
        self.session.cookies.set(
            "timestamp",
            timestamp_value,
            domain=self.captcha_session.service_url.replace("https://", ""),
        )
        self.session.headers = self.headers.headers()

        self.session.headers.update(
            {
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Origin": self.captcha_session.service_url,
                "Referer": f"{self.captcha_session.service_url}{enforcement_url}",
                "X-Ark-Esync-Value": str(int(time.time() / 21600) * 21600),
            }
        )

        if "roblox" in self.captcha_session.method:
            self._send_e()
            self.session.cookies.update(self.cookies)

        self.session.headers = sort_headers(self.session.headers)
        cfuidcookies = self.session.get(f"{self.captcha_session.service_url}/v2/{self.captcha_session.public_key}/api.js")
        
        self.session.cookies.update(cfuidcookies.cookies)

        task_form = construct_form_data(task)

        self.session.headers = sort_headers(self.session.headers)
        response = self.session.post(
            f"{self.captcha_session.service_url}/fc/gt2/public_key/{self.captcha_session.public_key}",
            data=task_form,
        )
        if response.status_code == 200:
            response_json: Dict[str, Any] = response.json()
            self.arkose_token = response_json["token"]
            if response_json["pow"]:
                self.pow()
            return self.arkose_token
        else:
            raise Exception(f"Failed to fetch Arkose token: {response.text}")

    def fetch_challenge_game(
        self, arkose_token: Optional[str] = None
    ) -> Optional[Game]:
        """
        Fetches an Arkose Labs challenge game.

        Args:
            arkose_token: The Arkose Labs challenge token.

        Returns:
            Game: The Arkose Labs challenge game, or None if the challenge token is invalid.
        """
        self.arkose_token = arkose_token if arkose_token else self.arkose_token

        def _parse_arkose_token(token: str) -> Dict[str, str]:
            token = "token=" + token
            token_data = {}
            for field in token.split("|"):
                key, value = field.partition("=")[0], field.partition("=")[-1]
                token_data[key] = value
            return token_data

        token_data = _parse_arkose_token(self.arkose_token)
        self.session_token = token_data["token"]
        self.session_id = token_data["r"]
        self.analytics_tier = token_data["at"]

        self.session.headers = self.headers.headers()
        if "sup" in token_data:
            url = f"{self.captcha_session.service_url}/fc/a/"
            params = {
                "callback": f"__jsonp_{int(round(time.time() * 1000))}",
                "category": "loaded",
                "action": "game loaded",
                "session_token": self.session_token,
                "data[public_key]": self.captcha_session.public_key,
                "data[site]": self.captcha_session.site_url,
            }
            self.session.headers = sort_headers(self.session.headers)
            self.session.get(url, params=params)
            return
        else:
            self.session.headers.update(
                {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Referer": f"{self.captcha_session.service_url}{enforcement_url}",
                    "Sec-Fetch-Dest": "iframe",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "same-origin",
                }
            )

            self.session.headers = sort_headers(self.session.headers)
            game_url = f"{self.captcha_session.service_url}/fc/assets/ec-game-core/game-core/1.27.4/standard/index.html?session={self.arkose_token.replace('|', '&')}&theme=default"
            self.session.get(game_url)

            self.session.headers.update(
                {
                    "Accept": "application/roblox, text/plain, */*",
                    "Referer": game_url,
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "same-origin",
                }
            )
            self.session.headers = sort_headers(self.session.headers)
            rc = self.session.get(
                f"{self.captcha_session.service_url}/fc/gc/?token={token_data['token']}"
            )

            self.session.cookies.update(rc.cookies)

            cookie, timestamp_value = self._get_timestamp()
            self.session.cookies.set(
                "timestamp",
                timestamp_value,
                domain=self.captcha_session.service_url.replace("https://", ""),
            )
            self.session.headers.update(
                {
                    "Accept": "*/*",
                    "X-Newrelic-Timestamp": timestamp_value,
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": self.captcha_session.service_url,
                    "Referer": game_url,
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "same-origin",
                }
            )
            data2 = {
                "token": self.session_token,
                "sid": self.session_id,
                "render_type": "canvas",
                "lang": f"{self.captcha_session.language if self.captcha_session.language is not None else ''}",
                "isAudioGame": False,
                "analytics_tier": self.analytics_tier,
                "is_compatibility_mode": False,
                "apiBreakerVersion": "green",
            }
            self.session.headers = sort_headers(self.session.headers)
            response = self.session.post(
                f"{self.captcha_session.service_url}/fc/gfct/", data=data2
            )
            if response.status_code == 200:
                game = Game(self.captcha_session, self, response.json())
            else:
                raise Exception(f"Failed to fetch game: {response.text}")

            game_token = game.challenge_id

            cookie, timestamp_value = self._get_timestamp()
            requested_id = aes_encrypt(
                json.dumps({"sc": [190, 253]}), f"REQUESTED{self.session_token}ID"
            )
            self.session.cookies.set(
                "timestamp",
                timestamp_value,
                domain=self.captcha_session.service_url.replace("https://", ""),
            )
            self.session.headers.update(
                {
                    "X-Newrelic-Timestamp": timestamp_value,
                    "X-Requested-ID": requested_id,
                    "X-Requested-With": "XMLHttpRequest",
                }
            )

            url_a = f"{self.captcha_session.service_url}/fc/a/"
            cookie, timestamp_value = self._get_timestamp()
            self.session.cookies.set(
                "timestamp",
                timestamp_value,
                domain=self.captcha_session.service_url.replace("https://", ""),
            )
            self.session.headers.update(
                {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": self.captcha_session.service_url,
                    "X-Newrelic-Timestamp": timestamp_value,
                    "X-Requested-With": "XMLHttpRequest",
                }
            )
            data1 = {
                "sid": self.session_id,
                "session_token": self.session_token,
                "analytics_tier": self.analytics_tier,
                "disableCookies": False,
                "render_type": "canvas",
                "is_compatibility_mode": False,
                "category": "Site URL",
                "action": f"{self.captcha_session.service_url}{enforcement_url}",
            }
            data1 = urlencode(data1)
            self.session.headers = sort_headers(self.session.headers)
            response = self.session.post(url_a, data=data1)

            data3 = {
                "sid": self.session_id,
                "session_token": self.session_token,
                "analytics_tier": self.analytics_tier,
                "disableCookies": False,
                "game_token": game_token,
                "game_type": game.type,
                "render_type": "canvas",
                "is_compatibility_mode": False,
                "category": "begin app",
                "action": "user clicked verify",
            }
            data3 = urlencode(data3)
            self.session.headers = sort_headers(self.session.headers)
            response = self.session.post(url_a, data=data3)

            return game


    def send_enforcement_callback(self):
        url1: str = f"{self.captcha_session.service_url}/v2/{capi_version}/enforcement.{enforcement_hash}.html"
        url2: str = f"{self.captcha_session.service_url}/v2/{capi_version}/enforcement.{enforcement_hash}.js"
        self.session.headers = sort_headers(self.session.headers)
        for url in [url1, url2]:
            self.session.get(url)


    def pow(self):
        def pows(powSeed, powLeadingZeroCount):
            interactions = 0
            start = random.randint(2000, 4000)
            while True:
                interactions +=1
                randomString = "".join(random.choices(string.ascii_lowercase + string.digits, k=15))
                hash = sha512((powSeed + randomString).encode()).hexdigest()
                if hash[:powLeadingZeroCount] == "0" * powLeadingZeroCount:
                    execTime = start - random.randint(1000, 1500)
                    return {
                        "result": randomString,
                        "execution_time": round(execTime),
                        "iteration_count": interactions,
                        "hash_rate": interactions / execTime
                    }
        
        headers = {
            'Accept': '*/*',
            'Accept-Language': self.session.headers["Accept-Language"],
            "Origin": self.captcha_session.service_url,
            'Referer': self.captcha_session.service_url + enforcement_url,
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': self.session.headers.get("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"),
            'sec-ch-ua': self.session.headers.get("Sec-Ch-Ua", '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"'),
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': self.session.headers.get("Sec-Ch-Ua-Platform", '"Windows"'),
        }

        self.session.headers.update(headers)

        params = {
            "session_token": self.arkose_token.split("|")[0],
        }

        self.session.headers = sort_headers(self.session.headers)
        url = f"{self.captcha_session.service_url}/pows/setup"
        response = self.session.get(url, params=params)
        
        if response.status_code != 200:
            raise Exception(f"Failed to fetch pow setup: {response.text}")

        powjson = response.json()
        powSeed = powjson["seed"]
        powLeadingZeroCount = powjson["leading_zero_count"]
        token = powjson["pow_token"]

        
        powsolve = pows(powSeed, powLeadingZeroCount)

        powdata = {
            "session_token": str(self.arkose_token.split("|")[0]),
            "pow_token": str(token),
            "result": str(powsolve["result"]),
            "execution_time": powsolve["execution_time"],
            "iteration_count": powsolve["iteration_count"],
            "hash_rate": powsolve["hash_rate"]
        }

        self.session.headers["Content-Type"] = "text/plain;charset=UTF-8"

        self.session.headers = sort_headers(self.session.headers)
        url = f"{self.captcha_session.service_url}/pows/check"
        response = self.session.post(url, json=powdata, headers=headers)

        if response.status_code != 200:
            raise Exception(f"Failed to verify pow: {response.text}")

        rfjson = response.json()
        if rfjson.get("action", None) == None:
            raise Exception("POW failed")
    
    def _send_e(self):
        # https://www.roblox.com/arkose/iframe?publicKey=476068BF-9607-4799-B53D-966BE98E2B81&dataExchangeBlob=GBcLBhV1U2W7XaD7.zJw67MevA5CokwtRk%2FVKiNGi3lf2ZieDES4ymmzdUXhXAouCErCC4XA7yYa3%2FCTIo7UMMjJsPz6OUBUTMzVdH1VRyuIRo2eu7PlG1PlRSilS7mDBlV7W0iFHZqs7zcGWD%2BwC0UWJANwiLK2%2FLbxUSPblcNetWcF1tyT1K1yuInhlNaTAfIMXFDRRKWWl5b%2B9ULUw6Uk8tpUZlx9ezR45WRVa2Qp6DcWd3X03Y%2F4KeI6f10TzbIxV9DOc5vuB4G7djo%2FgGq9l%2FKKJdMz4Pg%2B8otWfdO5YRMIalgTaxVNoQFaFlxSB8HK0qJbj%2FXvEAPa14w7V2pS1IMffgaRZabIQqMyGdRW53uqjGfb%2F0dX8BDZiKHb5CH5Y63FOS1wHuBEXiAOJ%2F0jIa3PyMG9Gf8SFsODtVsQxK7OFNCMUV6jTyagobxoTbC1PcdfFD%2BKJHJzhgIFq9NDU5S0yef3k%2BGwMw0JcPJnL%2Ftj2kwtYx9oVab70waB6zwjog6YdfL8iyXjGKW1efbHR7YGY0Yhmp%2BZiq168Sg5sU25Fnsi7pTqTu%2F%2FbS9QbVkLZ&arkoseIframeId=0
        
        url = f"https://www.roblox.com/arkose/iframe"
        
        params = {
            "publicKey": self.captcha_session.public_key,
            "dataExchangeBlob": self.captcha_session.blob,
            "arkoseIframeId": "0"
        }

        self.session.headers = sort_headers(self.session.headers)
        self.session.get(url, params=params, allow_redirects=True)