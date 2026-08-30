import json
from importlib.resources import files


def get_default_config() -> dict:
    asset = files("py_vault").joinpath("assets/default_config.json")

    with asset.open("r", encoding="utf-8") as file:
        return json.load(file)
