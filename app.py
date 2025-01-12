import concurrent.futures
import json
import logging
import os
import random
import secrets
import time
import traceback
import uuid
import base64

from hashlib import md5
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

import flask
from flask import Flask, request, Response, jsonify, render_template

from src.arkose_session.challenge import ChallengeSession
from src.arkose_session.game import Game
from src.bda.bda_template import FunCaptchaSession
from src.image.botmasterlabs import XEvil
from src.utilities.logger import log

DEBUG: bool = False
ONLY_PRINT_SOLVED: bool = False
DEFAULT_METHOD = "roblox_signup"

FILE_LOCK = Lock()
FILE_LOCK_2 = Lock()
COUNTS_LOCK = Lock()

app = Flask(__name__)
log_console = logging.getLogger("werkzeug")
log_console.disabled = True

SUPPORTED_BROWSERS: List[str] = [
    "chrome",
    "opera",
    "edge",
    "firefox",
    "chrome mac",
    "firefox mac",
    "chrome linux",
    "firefox linux",
    "safari",
]

SUPPORTED_OS: List[Tuple[str, str]] = [
    ("windows", "Windows NT 10.0; Win64; x64"),
    ("mac", "Macintosh; Intel Mac OS X 14_7_1"),
    ("linux", "Linux x86_64"),
]

REQUEST_COUNTER = 0

with open("keys.txt", "r") as f:
    raw_lines = f.read().splitlines()

KEYS_LIST: List[List[Any]] = []
for line in raw_lines:
    key_val, bought, tstamp, solved, totalr = line.split(",")
    KEYS_LIST.append([
        key_val.strip(),
        int(bought.strip()),
        int(tstamp.strip()),
        int(solved.strip()),
        int(totalr.strip()),
    ])

def write_keys_to_file(keys_data: List[List[Any]]) -> None:
    """
    Overwrite the entire 'keys.txt' file with the contents 
    of the passed-in list of keys.
    """
    with FILE_LOCK_2:
        with open("keys.txt", "w") as f:
            for item in keys_data:
                f.write(f"{item[0]},{item[1]},{item[2]},{item[3]},{item[4]}\n")


def append_key_to_file(key_str: str, bought: int) -> None:
    """
    Append a single new key to 'keys.txt'.
    """
    with FILE_LOCK_2:
        with open("keys.txt", "a") as f:
            f.write(f"{key_str},{bought},{int(time.time())},0,0\n")


def process_wave(game: Game, image_base64: str) -> str:
    """
    Helper function to predict the answer for a single captcha wave.
    """
    return XEvil.solveImage(image_base64, game.game_variant)


@app.route("/admin/generateAPIkey/sellix", methods=["POST", "GET"])
def generate_api_key() -> Tuple[flask.Response, int]:
    """
    Generates and returns a new API key after a purchase. 
    The quantity determines how many solves are allowed.
    """
    data: Dict[str, Any] = request.get_json()["data"]
    quantity: int = int(data.get("quantity", 1))
    bought: int = 1000 * quantity
    prefix: str = "D-CAP#"

    token_part: str = (
        str(random.randint(0, 9999))
        + str(secrets.token_hex(8))
        + str(uuid.uuid4().hex[:12])
    ).upper()

    new_key: str = (prefix + token_part).upper()
    KEYS_LIST.append([new_key, bought, int(time.time()), 0, 0])
    append_key_to_file(new_key, bought)

    return new_key

def saveimg(imagease64, variant):
    try:
        with open(f"storage/{variant}/{md5(base64.b64decode(imagease64).decode('utf-8')).hexdigest()}.png", "wb") as f:
            f.write(base64.b64decode(imagease64))
    except FileExistsError:
        os.makedirs(f"storage/{variant}", exist_ok=True)
        saveimg(imagease64, variant)
    return

@app.route("/classify", methods=["GET", "POST"])
def image_classifier() -> tuple[Response, int] | Response:
    """
    Stub route for image classification. Currently not implemented.
    """
    try:
        data = request.get_json()
        variant = data["variant"]


        images = data["images"]

        if images:
            threads = len(images)
            reslst = []
            for image in images:
                saveimg(image, variant)
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                futures = [executor.submit(process_wave, image, variant) for image in images]
                for future in concurrent.futures.as_completed(futures):
                    reslst.append(future.result())
                
            return jsonify({"predictions": reslst}), 200

        return jsonify({"error": "No images provided"}), 400
    
    except Exception as e:
        log.log_debug(f"Error: {e}")
        return jsonify({"error": str(e)}), 500  


@app.route("/solve", methods=["GET", "POST"])
def image_solver() -> tuple[Response, int] | Response:
    """
    Main route for solving Arkose-based CAPTCHAs. 
    Handles:
    - Key validation
    - Proxy validation
    - Browser/OS validation
    - Challenge execution and solution 
    - Real-time usage updates in 'keys.txt'
    """
    global REQUEST_COUNTER

    with COUNTS_LOCK:
        REQUEST_COUNTER += 1

    if request.method != "POST":
        return (
            jsonify(
                {
                    "error": "Please use method 'POST' for this.",
                    "method": f"{request.method}",
                    "requests": REQUEST_COUNTER,
                }
            ),
            400,
        )

    request_data: Dict[str, Any] = request.get_json()
    method: Optional[str] = request_data.get("method", None)
    proxy: Optional[str] = request_data.get("proxy", None)
    blob: Optional[str] = request_data.get("blob", None)

    browser: Optional[str] = request_data.get("browser", None)
    version: Optional[str] = request_data.get("version", None)
    os_: Optional[str] = request_data.get("os", None)
    accept_language: Optional[str] = request_data.get("Accept-Language", None)

    cookies = request_data.get("cookies", None)

    key = "D-CAP#ADMIN45745878896"

    if not proxy:
        return jsonify({"error": "proxy is required.", "requests": REQUEST_COUNTER}), 400

    if not method:
        return (
            jsonify(
                {
                    "error": "method is required.",
                    "methods": [
                        "outlook",
                        "twitter",
                        "twitter_unlock",
                        "roblox_signup",
                        "roblox_login",
                        "roblox_join",
                        "ea",
                        "github-signup",
                        "demo",
                        "roblox_wall",
                        "airbnb-register",
                    ],
                    "info": "Site is not in here? Contact the developer. (@trailios or admin@bombing.lol)",
                    "requests": REQUEST_COUNTER,
                }
            ),
            400,
        )

    if browser not in SUPPORTED_BROWSERS:
        return (
            jsonify(
                {
                    "error": "browser is not supported.",
                    "supported": SUPPORTED_BROWSERS,
                    "requests": REQUEST_COUNTER,
                }
            ),
            400,
        )
    matched_os: Optional[str] = None
    for os_key, os_header in SUPPORTED_OS:
        if os_key.lower() == str(os_).lower():
            matched_os = os_header
            break
    if not matched_os:
        return (
            jsonify(
                {
                    "error": "os is not supported.",
                    "supported": [o[0] for o in SUPPORTED_OS],
                    "requests": REQUEST_COUNTER,
                }
            ),
            400,
        )

    if not key:
        return (
            jsonify({"error": "key is required.", "requests": REQUEST_COUNTER}),
            400,
        )

    for pkey in KEYS_LIST:
        if pkey[0] == key:
            key_index = KEYS_LIST.index(pkey)
            break
    else:
        return (
            jsonify({"error": "D-CAP-ERR: KEY IS INVALID.", "requests": REQUEST_COUNTER}),
            400,
        )

    if KEYS_LIST[key_index][3] >= KEYS_LIST[key_index][1]:
        return (
            jsonify({"error": "D-CAP-ERR: BALANCE IS EMPTY", "requests": REQUEST_COUNTER}),
            400,
        )

    with FILE_LOCK_2:
        KEYS_LIST[key_index][4] += 1


    try:
        fun_captcha_session: FunCaptchaSession = FunCaptchaSession(method=method, blob=blob)
        challenge: ChallengeSession = ChallengeSession(
            fun_captcha_session,
            proxy=proxy,
            browser_data=(browser, version, matched_os, accept_language, cookies),
            timeout=45,
        )
    except Exception as exc:
        if DEBUG:
            log.log_debug(f"Error initializing sessions: {exc}")
        return (
            jsonify({"error": f"Error: {exc}", "requests": REQUEST_COUNTER}),
            400,
        )

    try:
        arkose_token: str = challenge.fetch_challenge_token()

        if "sup=1" in arkose_token:
            challenge.fetch_challenge_game(arkose_token)
            log.solved_captcha(
                token=arkose_token.split("|")[0],
                waves="N/A",
                variant="Silent-Pass",
                browser=challenge.headers.browser,
            )
            with FILE_LOCK_2:
                KEYS_LIST[key_index][3] += 1
            write_keys_to_file(KEYS_LIST)
            return Response(
                json.dumps(
                    {
                        "msg": "success",
                        "solved": True,
                        "token": arkose_token,
                        "requests": REQUEST_COUNTER,
                    }
                ),
                content_type="application/json",
            )

        game: Game = challenge.fetch_challenge_game(arkose_token)
        if DEBUG:
            log.log_debug(
                f"Captcha Information / Variant: {game.game_variant} / "
                f"Type: {game.type} / Difficulty: {game.difficulty} / "
                f"Waves: {game.waves} | Browser: {challenge.headers.browser}"
            )
        game.pre_get_image()

        answers: Dict[str, Any] = {}
        answer_result: Dict[str, Any] = {"solved": False}

        with concurrent.futures.ThreadPoolExecutor(max_workers=game.waves + 1) as executor:
            futures = []
            for wave_index in range(game.waves):
                image_base64, image_file_path, image_md5 = game.get_image(
                    wave_index, download=True
                )
                future = executor.submit(process_wave, game, image_base64)
                futures.append((future, wave_index, image_md5, image_file_path))

            for future, wave_index, image_md5, image_file_path in futures:
                answer = future.result()
                answers[image_file_path] = answer
                answer_result = game.put_answer(wave_index, answer)
                if DEBUG:
                    log.log_debug(
                        f"Captcha Wave: {wave_index + 1} / "
                        f"Answer: {answer} / Image-MD5: {image_md5}"
                    )

        result_payload: Dict[str, Any] = {
            "msg": "success",
            "solved": answer_result["solved"],
            "token": challenge.arkose_token,
            "requests": REQUEST_COUNTER,
        }


        if answer_result["solved"]:
            log.solved_captcha(
                token=arkose_token.split("|")[0],
                waves=str(game.waves),
                variant=str(game.game_variant),
                browser=challenge.headers.browser,
            )
            with FILE_LOCK_2:
                KEYS_LIST[key_index][3] += 1
            write_keys_to_file(KEYS_LIST)
            return Response(
                json.dumps(result_payload), 
                content_type="application/json"
            )
        else:
            if ONLY_PRINT_SOLVED:
                return Response(
                    json.dumps(result_payload), 
                    content_type="application/json"
                )
            result_payload["msg"] = "failed"
            log.failed_captcha(
                token=arkose_token.split("|")[0],
                waves=str(game.waves),
                variant=str(game.game_variant),
                browser=challenge.headers.browser,
            )
            write_keys_to_file(KEYS_LIST)
            return Response(
                json.dumps(result_payload), 
                content_type="application/json"
            )

    except Exception as exc:
        error_payload = {
            "msg": f"Failed: {exc} --> Please contact '@trailios' on Discord.",
            "solved": False,
            "token": challenge.arkose_token,
            "requests": REQUEST_COUNTER,
        }
        write_keys_to_file(KEYS_LIST)
        if DEBUG:
            tb = traceback.extract_tb(exc.__traceback__)
            full_path = tb[-1].filename
            filename = os.path.basename(full_path)
            line_no = tb[-1].lineno
            log.log_debug(f"{exc}, line {line_no} in {filename}")

        return Response(
            json.dumps(error_payload),
            content_type="application/json",
            status=500
        )


@app.route("/", methods=["GET"])
def home() -> Tuple[flask.Response, int]:
    """
    Renders a simple index.html page. 
    """
    return render_template("index.html"), 200


if __name__ == "__main__":
    try:
        os.system("clear" if os.name == "posix" else "cls")
        app.run(host="0.0.0.0", port=6670)
    except KeyboardInterrupt as e:
        log.log_info(f"Shutting down... {e}")
        write_keys_to_file(KEYS_LIST)
