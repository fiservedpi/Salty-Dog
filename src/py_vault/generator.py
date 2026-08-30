import secrets
from importlib.resources import files


def load_wordlist() -> list[str]:
    wordlist_file = files("py_vault").joinpath(
        "assets",
        "wordlist.txt",
    )

    words = [
        line.strip()
        for line in wordlist_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

    if not words:
        raise ValueError("The bundled wordlist is empty.")

    return words


def generate_passphrase(words_count: int = 6, separator: str = "-") -> str:
    if words_count < 3:
        raise ValueError("Use at least 3 words.")

    words = load_wordlist()
    return separator.join(
        secrets.choice(words)
        for _ in range(words_count)
    )