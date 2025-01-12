import urllib.parse
from typing import Dict, Any


def construct_form_data(data: Dict[str, Any]) -> str:
    filtered_data: Dict[str, Any] = {
        key: value for key, value in data.items() if value is not None
    }
    encoded_data: list[str] = [
        f"{key}={urllib.parse.quote(str(value), safe='()')}"
        for key, value in filtered_data.items()
    ]
    form_data: str = "&".join(encoded_data)
    return form_data
