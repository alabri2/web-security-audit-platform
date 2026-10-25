import re


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
BRACKET_COLOR_RE = re.compile(r"\[[0-9;]*m")


def clean_text(text: str) -> str:
    if not text:
        return ""

    text = str(text)
    text = ANSI_ESCAPE_RE.sub("", text)
    text = BRACKET_COLOR_RE.sub("", text)
    text = text.replace("\r", "")
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def clean_evidence(text: str, max_lines: int = 8, max_chars: int = 700) -> str:
    text = clean_text(text)
    if not text:
        return ""

    lines = [line.strip() for line in text.splitlines() if line.strip()]

    useful_lines = []
    for line in lines:
        low = line.lower()


        if low in {"_", "-", "--", "---"}:
            continue
        if len(line) < 2:
            continue

        useful_lines.append(line)

    useful_lines = useful_lines[:max_lines]
    result = "\n".join(useful_lines)

    if len(result) > max_chars:
        result = result[:max_chars].rsplit(" ", 1)[0] + " ..."

    return result.strip()


def clean_title(text: str) -> str:
    text = clean_text(text)
    return text[:180].strip() if text else "Untitled finding"


def clean_description(text: str) -> str:
    text = clean_text(text)
    if not text:
        return "No description provided."
    if len(text) > 500:
        text = text[:500].rsplit(" ", 1)[0] + " ..."
    return text.strip()
