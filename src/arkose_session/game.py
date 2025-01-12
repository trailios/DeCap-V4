import base64, hashlib, json, os, random, re, string
import execjs

from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple, Union
from PIL import Image
from urllib.parse import urlencode

from src.arkose_session.bio import DataGenerator
from src.arkose_session.crypto import aes_encrypt, aes_decrypt


def remove_all_html_tags(text: str) -> str:
    pattern = re.compile(r"<[^>]+>")
    return pattern.sub("", text)


def calculate_coordinates(
    answer_index: int, layouts: Dict[str, Any]
) -> Dict[str, float]:
    columns = layouts["columns"]
    rows = layouts["rows"]
    tile_width = layouts["tile_width"]
    tile_height = layouts["tile_height"]
    if not 0 <= answer_index < columns * rows:
        raise ValueError(f"The answer should be between 0 and {columns * rows}")
    x = (answer_index % columns) * tile_width
    y = (answer_index // columns) * tile_height
    px = round(random.uniform(0, tile_width), 2)
    py = round(random.uniform(0, tile_height), 2)
    return {"px": px, "py": py, "x": x, "y": y}


def flagged(data: list) -> bool:
    if not data or not isinstance(data, list):
        return False
    values = [value for d in data for value in d.values()]
    if not values:
        return False

    def ends_with_uppercase(value):
        return value and value[-1] in string.ascii_uppercase

    return all(ends_with_uppercase(value) for value in values)


def pguesses(guesses: list, token: str) -> list:
    sess: str
    ion: str

    sess, ion = token.split(".")
    answers: list = []

    for guess in guesses:
        if "index" in guess:
            answers.append({"index": guess["index"], sess: ion})
        else:
            guess: dict = json.loads(guess)
            answers.append(
                {
                    "px": guess["px"],
                    "py": guess["py"],
                    "x": guess["x"],
                    "y": guess["y"],
                    sess: ion,
                }
            )

    return answers


def process(dapib_code: str, answers: list) -> list:
    tries = 0
    while True:
        tries += 1
        try:
            ctx = execjs.compile(
                """
            function runCode(dapibCode, answers) {
                window = {};
                window.parent = {};
                window.parent.ae = {"answer": answers};
                window.parent.ae["dapibRecei" + "ve"] = function(data) {
                    response = JSON.stringify(data);
                };
                
                eval(dapibCode);
                return response;
            }
            """
            )

            result: str = ctx.call("runCode", dapib_code, answers)
            result: dict = json.loads(result)

            if flagged(result["tanswer"]):
                for array in result["tanswer"]:
                    for item in array:
                        array[item] = (
                            array[item][:-1] if isinstance(array[item], str) else array[item]
                        )

            return result["tanswer"]
        
        except Exception as e:
            if tries > 5:
                raise Exception("Failed to process tguess answers: " + str(e))
            continue

def main(dapib_code: str, token: str, guesses: list) -> list:
    try:
        answers: list = pguesses(guesses, token)
        result: list = process(dapib_code, answers)

    except Exception as e:
        raise Exception("Failed to process tguess answers: " + str(e))

    return result


class Game:
    def __init__(
        self,
        captcha_session: Any,
        challenge_session: Any,
        response_session: Dict[str, Any],
    ) -> None:
        self.captcha_session = captcha_session
        self.challenge_session = challenge_session

        self.session_token: str = response_session["session_token"]
        self.challenge_id: str = response_session["challengeID"]
        self.challenge_url: str = response_session["challengeURL"]

        self.dapib_url: Optional[str] = response_session.get("dapib_url")

        self.data: Dict[str, Any] = response_session["game_data"]
        self.type: int = self.data["gameType"]
        self.waves: int = self.data["waves"]
        self.difficulty: Optional[str] = (
            self.data.get("game_difficulty") if self.type == 4 else None
        )

        self.encrypted_mode: Union[bool, int] = self.data["customGUI"].get(
            "encrypted_mode", False
        )
        self.ekey: str = None

        self.game_variant: str = (
            self.data.get("instruction_string")
            if self.type == 4
            else self.data["game_variant"]
        )

        if not self.game_variant:
            self.game_variant = "3d_rollball_animalss"
        self.customGUI: Dict[str, Any] = self.data["customGUI"]
        self.layouts: Optional[Dict[str, Any]] = (
            self.customGUI.get("_challenge_layouts") if self.type == 3 else None
        )

        self.image_urls: List[str] = self.customGUI["_challenge_imgs"]
        self.image_bytes: List[bytes] = []
        if self.game_variant == "3d_rollball_animalss":
            self.prompt: str = response_session["string_table"].get(
                f"{self.type}.instructions_{self.game_variant}", ""
            )

        else:
            self.prompt: str = response_session["string_table"].get(
                f"{self.type}.instructions-{self.game_variant}", ""
            )

        self.guess: List[Dict[str, Any]] = []
        self.tguess: List[Any] = []
        self.prompt_en: str = remove_all_html_tags(self.prompt)

    def pre_get_image(self) -> None:
        timestamp_cookie, timestamp_value = self.challenge_session._get_timestamp()
        self.challenge_session.session.cookies.set(
            "timestamp",
            timestamp_value,
            domain=self.captcha_session.service_url.replace("https://", ""),
        )
        if self.encrypted_mode == 1:
            payload: Dict[str, str] = {
                "session_token": self.session_token,
                "game_token": self.challenge_id,
                "sid": self.challenge_session.session_id,
            }

            ekeyurl = f"{self.captcha_session.service_url}/fc/ekey/"

            ekey: str = self.challenge_session.session.post(ekeyurl, data=payload)

            if ekey.status_code == 200:
                self.ekey = ekey.json()["decryption_key"]
            else:
                raise Exception("Failed to get ekey: " + ekey.text)

        for url in self.image_urls:
            response = self.challenge_session.session.get(url)
            if response.status_code == 200:

                imgbytes: bytes = None

                if self.encrypted_mode == 1:
                    rjson: Dict[str, str] = response.json()

                    imgbytes = aes_decrypt(rjson, self.ekey)
                else:
                    imgbytes = response.content

                self.image_bytes.append(imgbytes)
            else:
                raise Exception("Failed to get image: " + response.text)

    def get_image(
        self, number: int, show: bool = False, download: bool = False
    ) -> Tuple[str, str, str]:
        if len(self.image_bytes) == 0:
            self.pre_get_image()
        image_bytes = self.image_bytes[number]

        if show:
            image = Image.open(BytesIO(image_bytes))
            image.show()

        image_base64: str = base64.b64encode(image_bytes).decode("utf-8")
        image_md5: str = hashlib.md5(image_bytes).hexdigest()

        fold_file_path: str = os.path.join("./storage/images", self.game_variant)
        file_path: str = os.path.join(fold_file_path, f"{image_md5}")

        if download:
            if not os.path.exists(fold_file_path):
                os.makedirs(fold_file_path)
            with open(file_path + ".jpg", "wb") as image_file:
                image_file.write(image_bytes)

        return image_base64, file_path, image_md5

    def get_tguess_crypt(self) -> str:
        response = ""
        try:
            data: Dict[str, Any] = {
                "guess": self.guess,
                "dapib_url": self.dapib_url,
                "session_token": self.session_token,
            }

            dapi_code = self.challenge_session.session.post(self.dapib_url).text
            response = main(
                dapi_code,
                data["session_token"],
                data["guess"],
            )

            tguess_crypt: str = aes_encrypt(json.dumps(response), self.session_token)
            return tguess_crypt
        except Exception as e:
            raise Exception("Failed to get tguess: " + str(e))

    def put_answer(self, num: int, answer_index: int) -> Dict[str, Any]:
        if self.type == 4:
            answer: Dict[str, Any] = {"index": answer_index}
        elif self.type == 3:
            answer = calculate_coordinates(answer_index, self.layouts[num])
        self.guess.append(answer)
        guess_crypt: str = aes_encrypt(json.dumps(self.guess), self.session_token)

        answer_url: str = f"{self.captcha_session.service_url}/fc/ca/"

        if num + 1 == self.waves:
            self.challenge_session.session.headers.update(
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": f"{self.captcha_session.service_url}/fc/assets/ec-game-core/game-core/1.26.0/standard/index.html?session={self.challenge_session.arkose_token.replace('|', '&')}",
                }
            )
            answer_data: Dict[str, Any] = {
                "session_token": self.session_token,
                "game_token": self.challenge_id,
                "sid": self.challenge_session.session_id,
                "guess": guess_crypt,
                "render_type": "canvas",
                "analytics_tier": self.challenge_session.analytics_tier,
                "bio": str(DataGenerator().generate()),
                "is_compatibility_mode": False,
            }

            if self.dapib_url:
                tguess_crypt: str = self.get_tguess_crypt()
                answer_data["tguess"] = tguess_crypt

            timestamp_cookie, timestamp_value = self.challenge_session._get_timestamp()
            requested_id: str = aes_encrypt(
                json.dumps({"sc": [random.randint(1, 200), random.randint(1, 200)]}),
                f"REQUESTED{self.session_token}ID",
            )
            self.challenge_session.session.cookies.set(
                "timestamp",
                timestamp_value,
                domain=self.captcha_session.service_url.replace("https://", ""),
            )
            self.challenge_session.session.headers.update(
                {
                    "X-Newrelic-Timestamp": timestamp_value,
                    "X-Requested-ID": requested_id,
                    "X-Requested-With": "XMLHttpRequest",
                }
            )
            response = self.challenge_session.session.post(
                answer_url, data=urlencode(answer_data)
            )
            if response.status_code == 200:
                try:
                    self.ekey = response.json().get("decryption_key", False)
                except Exception:
                    self.ekey = False
                return response.json()
            else:
                raise Exception(
                    f"Failed to put answer: {str(response.status_code)} {str(response.text)}"
                )
