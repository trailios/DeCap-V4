import base64, json, os
import random, time

from curl_cffi import requests
from src.utilities.headers import Headers
from typing import Dict, Any, List

from src.bda.bda_template import FunCaptchaOptions
from src.config import enforcement_hash
from src.arkose_session.crypto import aes_encrypt
from src.utilities.hash import x64hash128


fingerprints: List[str] = os.listdir("database/fingerprints")


def update_fingerprint_data(
    decrypted_fingerprint: list[dict[str, str]], method: str, useragent: str
) -> list[dict[str, str]]:
    try:
        decrypted_fingerprint_dict: dict[str, str] = convert_json_to_dict(
            decrypted_fingerprint
        )
        enhanced_fingerprint_data: dict[str, str] = convert_json_to_dict(
            decrypted_fingerprint_dict["enhanced_fp"]
        )
        fun_captcha_options = FunCaptchaOptions(method=method, useragent=useragent)
        enhanced_fingerprint_data.update(fun_captcha_options.options)
        decrypted_fingerprint_dict["enhanced_fp"] = convert_dict_to_json(
            enhanced_fingerprint_data
        )
        decrypted_fingerprint: list[dict[str, str]] = convert_dict_to_json(
            decrypted_fingerprint_dict
        )
    except Exception as error:
        raise Exception("Unable to update fingerprint data: " + str(error))
    return decrypted_fingerprint


def prepare_fingerprint_data(fingerprint: dict) -> str:
    formatted_data = []
    for key, value in fingerprint.items():
        if isinstance(value, list):
            formatted_data.append(",".join(map(str, value)))
        else:
            formatted_data.append(str(value))
    return ";".join(formatted_data)


def prepare_fingerprint_entries(fp: dict) -> list[str]:
    formatted_entries = [f"{key}:{value}" for key, value in fp.items()]
    return formatted_entries


def parse_fingerprint_entries(fingerprint_entries: list[str]) -> dict:
    parsed_fp = {}
    for entry in fingerprint_entries:
        key, value = entry.split(":")
        parsed_fp[key] = value
    return parsed_fp


def identify_user_platform(user_agent: str) -> str:
    platform_mapping = {
        "iPhone": "iPhone",
        "Intel Mac OS": "MacIntel",
        "Windows": "Win32",
        "Android": lambda: random.choice(["Linux aarch64", "Linux armv7l"]),
        "Linux": "Linux x86_64",
    }
    return next(
        (
            (platform() if callable(platform) else platform)
            for platform_name, platform in platform_mapping.items()
            if platform_name in user_agent
        ),
        "Linux armv8",
    )


def getIpInfo(proxy: str = None) -> dict:
    headers = {
        "accept": "*/*",
        "accept-language": "de-DE,de;q=0.6",
        "cache-control": "no-cache",
        "next-router-prefetch": "1",
        "next-router-state-tree": "%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2F%22%2C%22refresh%22%5D%7D%2Cnull%2Cnull%2Ctrue%5D",
        "next-url": "/",
        "pragma": "no-cache",
        "priority": "u=1, i",
        "referer": "https://ipgeolocation.io/",
        "rsc": "1",
        "sec-ch-ua": '"Brave";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sec-gpc": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    }

    response = requests.get(
        "https://ipgeolocation.io/what-is-my-ip",
        headers=headers,
        proxies={"http": f"{proxy}", "https": f"{proxy}"},
    )

    match = re.search(r"current_time&quot;\s*:\s*&quot;([^&]+)", response.text)
    istor = re.search(r"is_tor&quot;\s*:\s*(true|false)", response.text)
    threat = re.search(r"threat_score&quot;\s*:\s*(\d+)", response.text)
    isbot = re.search(r"is_bot&quot;\s*:\s*(true|false)", response.text)
    isspam = re.search(r"is_spam&quot;\s*:\s*(true|false)", response.text)

    if match:
        current_time = match.group(1)
        timezoneOffset = (
            current_time[-3] if current_time[-4] == "0" else current_time[-4:-2]
        )
        timezoneOffset = (
            -int(timezoneOffset) * 60
            if current_time[-5] == "+"
            else int(timezoneOffset) * 60
        )
        # print(f"TO: {timezoneOffset}")
        # print(f"TOR: {istor.group(1)}")
        # print(f"THREAT: {threat.group(1)}")
        # print(f"BOT: {isbot.group(1)}")
        # print(f"SPAM: {isspam.group(1)}")

        return timezoneOffset
    else:
        raise ValueError("No valid current_time found in the input data.")


def convert_json_to_dict(json_data: list[dict[str, str]]) -> dict[str, str]:
    result_dict: dict[str, str] = {}
    for item in json_data:
        key: str = item.get("key")
        value: str = item.get("value")
        result_dict[key] = value
    return result_dict


def convert_dict_to_json(original_dict: dict[str, str]) -> list[dict[str, str]]:
    json_data: list[dict[str, str]] = [
        {"key": key, "value": value} for key, value in original_dict.items()
    ]
    return json_data


def generate_browser_data(
    headers: Headers, method: str = None, proxy=None, custom_headers=None
) -> tuple[str, str, str, Dict[Any, Any]]:

    headerdict = headers.headers()

    if custom_headers:
        headerdict.update(custom_headers)

    user_agent: str = headerdict["User-Agent"]
    accept_language = headerdict["Accept-Language"]

    realfpbool: bool = True # 10 waves on real fp, 6-7 waves on generated fp cba why

    if realfpbool:
        realfp = random.choice(fingerprints)
        with open("database/fingerprints/" + realfp, "r", encoding="utf-8") as f:
            realfingerprint = json.load(f)

        timestamprfp = time.time()

        realfpdict = convert_json_to_dict(realfingerprint)
        enhacnedfpdict = convert_json_to_dict(realfpdict["enhanced_fp"])
        realfpdict["n"] = (
            base64.b64encode(str(int(timestamprfp)).encode("utf-8")).decode("utf-8"),
        )
        enhacnedfpdict["1l2l5234ar2"] = str(int(timestamprfp * 1000)) + "\u2063"
        enhacnedfpdict["6a62b2a558"] = str(enforcement_hash)
        enhacnedfpdict["29s83ih9"] = "68934a3e9455fa72420237eb05902327" + "\u2063"

        if "roblox" in method:
            enhacnedfpdict["d4a306884c"] = "Ow=="
            enhacnedfpdict["4ca87df3d1"] = "Ow=="
            enhacnedfpdict["867e25e5d4"] = "Ow=="
        else:
            enhacnedfpdict["d4a306884c"] = "NiwwLDEyMTEsMzIyOzE0LDAsMTE5MiwzMDI7MzUsMCw5ODMsMTc0OzUyLDAsODMzLDE1Mjs2OCwwLDY5MSwxNzg7ODUsMCw1NzUsMjUyOzEwMiwwLDUxNywzNDU7MTE4LDAsNTA1LDQ1MjsxMzUsMCw1NDUsNTU4OzE1MSwwLDYyNSw2NDM7MTY4LDAsNzM3LDY5NzsxODUsMCw4NDEsNzA3OzIwMiwwLDkxOSw2Nzk7MjE4LDAsOTUxLDYyNDsyMzUsMCw5NDEsNTM2OzI1MSwwLDg3Myw0NDI7MjY4LDAsNzU0LDM3MjsyODUsMCw2MTgsMzU2OzMwMSwwLDQ4NSwzOTI7MzE4LDAsMzYwLDQ2NTszMzUsMCwyNzgsNTQ3OzM1MSwwLDIzOCw2MTk7MzY4LDAsMjI5LDY3MjszODUsMCwyMzQsNzAyOzQwMSwwLDI0Niw3MDY7NDE4LDAsMjc4LDY4OTs0MzUsMCwzMzYsNjM0OzQ1MSwwLDQxOSw1NTM7NDY4LDAsNTE0LDQ3NDs0ODUsMCw1OTksNDE4OzUwMSwwLDY0MSw0MDI7NTE4LDAsNjUyLDQxNTs1MzUsMCw2NTcsNDc4OzU1MSwwLDY1Nyw1NzU7NTY4LDAsNjc3LDY5ODs1ODUsMCw3MjUsODExOzYwMSwwLDc4MSw4ODU7NjE4LDAsODMyLDkxOTs2MzUsMCw4NjUsOTE1OzY1MSwwLDg5MSw4ODQ7NjY4LDAsOTIzLDgyMTs2ODUsMCw5NjIsNzI4OzcwMSwwLDEwMDIsNjI3OzcxOCwwLDEwMzUsNTI4OzczNSwwLDEwNDQsNDY1Ozc1MSwwLDEwMzUsNDM4Ozc2OCwwLDEwMTIsNDM0Ozc4NiwwLDk3Myw0NTA7ODAxLDAsOTMwLDQ4NDs4MTgsMCw4ODgsNTQ0OzgzNSwwLDg0OSw2Mzg7ODUxLDAsODE3LDczNzs4NjgsMCw3OTQsODI1Ozg4NSwwLDc4MSw4NzI7OTAxLDAsNzY5LDg4Mjs5MTgsMCw3MzYsODYzOzkzNSwwLDY0OSw3ODU7OTUxLDAsNTMwLDY4ODs5NjgsMCw0MDcsNTkyOzk4NSwwLDMyOSw1Mjg7MTAwMSwwLDMxNiw1MDk7MTAxOCwwLDM0Nyw1MDc7MTAzNSwwLDQ2NSw1Mjk7MTA1MSwwLDYzNiw1Nzk7MTA2OCwwLDgzOCw2NTY7MTA4NSwwLDEwMTksNzQ0OzExMDEsMCwxMTQ5LDgxNDsxMTE4LDAsMTIzNSw4NTM7MTEzNSwwLDEyNzQsODU3OzExNTEsMCwxMjg0LDgyODsxMTY4LDAsMTI2OCw3NTA7MTE4NSwwLDEyMTYsNjM2OzEyMDEsMCwxMTM2LDUxNTsxMjE4LDAsMTAyNCw0MTM7MTIzNSwwLDkxNSwzNzg7"
            enhacnedfpdict["4ca87df3d1"] = "Ow=="
            enhacnedfpdict["867e25e5d4"] = "Ow=="

        felist = realfpdict["fe"]

        data_dict = {item.split(":")[0]: item.split(":")[1] for item in felist}
        data_dict["L"] = accept_language.split(",")[0]
        data_dict["TO"] = str(getIpInfo(proxy))
        #data_dict["JSF"] = None
        data_list = [f"{key}:{value}" for key, value in data_dict.items()]
        
        data_entries = prepare_fingerprint_entries(data_dict)


        realfpdict["fe"] = data_list
        realfpdict["f"] = x64hash128(prepare_fingerprint_data(data_dict), 0)
        realfpdict["ife_hash"] = x64hash128(", ".join(data_entries), 38)
        realfpdict["enhanced_fp"] = convert_dict_to_json(enhacnedfpdict)

        realfingerprint = convert_dict_to_json(realfpdict)
        realfingerprint = update_fingerprint_data(realfingerprint, method, user_agent)
        realfingerprintjson = json.dumps(realfingerprint, separators=(",", ":"))
        realfpencrypted_data = aes_encrypt(
            realfingerprintjson,
            f"{user_agent}{str(int(time.time() - int((time.time() % 21600))))}",
        )
        base64_encrypted_data = base64.b64encode(
            realfpencrypted_data.encode("utf-8")
        ).decode("utf-8")

        return (
            base64_encrypted_data,
            user_agent,
            realfingerprintjson,
            {},
        )
