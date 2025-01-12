import logging, random
from enum import Enum
from typing import Any, Dict
from colorama import Fore, Style, init

init(autoreset=True)

SUCCESS_LEVEL_NUM = 25
logging.addLevelName(SUCCESS_LEVEL_NUM, "SUCCESS")


def success(self, message, *args, **kwargs):
    if self.isEnabledFor(SUCCESS_LEVEL_NUM):
        self._log(SUCCESS_LEVEL_NUM, message, args, **kwargs)


logging.Logger.success = success


class LogLevel(Enum):
    DEBUG = (Fore.MAGENTA, "DEBUG")
    INFO = (Fore.BLUE, "INFO")
    SUCCESS = (Fore.LIGHTGREEN_EX, "SUCCESS")
    WARNING = (Fore.YELLOW, "WARNING")
    ERROR = (Fore.LIGHTRED_EX, "FAILURE")
    CRITICAL = (Fore.RED, "CRITICAL")


class CustomFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        level = (
            LogLevel[record.levelname]
            if record.levelname in LogLevel.__members__
            else None
        )
        color = level.value[0] if level else ""
        prefix = f"{color}[{record.levelname:^10}]{Style.RESET_ALL}"
        colored_message = f"{prefix} {message}{Style.RESET_ALL}"
        record.msg = colored_message
        return super().format(record)


class Logger:
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        handler = logging.StreamHandler()
        handler.setFormatter(CustomFormatter())
        self.logger.addHandler(handler)

    def _log_captcha(self, level: LogLevel, data: Dict[str, Any]):
        message = (
            f"{Fore.LIGHTBLUE_EX}{'TOKEN:':<5} {data['token']:>35} {Style.RESET_ALL}| "
            f"{Fore.LIGHTBLACK_EX}{'WAVES:':<5} {data['waves']:>3} {Style.RESET_ALL}| "
            f"{Fore.LIGHTCYAN_EX}{'VARIANT:':<5} {data['variant'].upper():>19}{Style.RESET_ALL} | "
            f"{Fore.LIGHTBLACK_EX} {'BROWSER:':<7} {data['browser'].upper():>12} {Style.RESET_ALL}"
        )
        getattr(self.logger, level.name.lower())(message)

    def solved_captcha(
        self,
        token: str,
        waves: Any,
        variant: str,
        status: str = "Success",
        browser: str = "Chrome",
    ):
        self._log_captcha(
            LogLevel.SUCCESS,
            {
                "token": token,
                "waves": waves,
                "variant": variant,
                "status": "Success",
                "browser": browser,
            },
        )

    def failed_captcha(
        self,
        token: str,
        waves: Any,
        variant: str,
        status: str = "Failure",
        browser: str = "Chrome",
    ):
        self._log_captcha(
            LogLevel.ERROR,
            {
                "token": token,
                "waves": waves,
                "variant": variant,
                "status": "Failure",
                "browser": browser,
            },
        )

    def log_info(self, message: str):
        self.logger.info(f"{Fore.BLUE}{message}")

    def log_debug(self, message: str):
        self.logger.debug(f"{Fore.MAGENTA}{message}")


log = Logger(__name__)

