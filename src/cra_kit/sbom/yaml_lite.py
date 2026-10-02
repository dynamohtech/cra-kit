"""A small YAML reader for machine-written lockfiles (pnpm-lock.yaml, yarn.lock v2+).

cra-kit has no runtime dependencies, so it cannot use PyYAML. Lockfiles use a
narrow, regular subset of YAML: block mappings and sequences with space
indentation, plain / single-quoted / double-quoted scalars, and simple flow
collections such as ``{integrity: sha512-...}`` or ``[x64]``. This module
reads exactly that subset. Every scalar comes back as a string (no type
guessing), an empty value as ``None``, and anything outside the subset raises
``ValueError`` rather than being misread.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

_BLOCK_INDICATOR = re.compile(r"^[|>][+-]?[1-9]?[+-]?(\s+#.*)?$")
_ESCAPES = {
    "0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\v", "f": "\f", "r": "\r",
    "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0", "L": "\u2028",
    "P": "\u2029",
}
_HEX_ESCAPES = {"x": 2, "u": 4, "U": 8}


class _Unterminated(ValueError):
    """A quoted scalar continues on the next line."""


@dataclass
class _Line:
    indent: int
    text: str
    number: int


def load(text: str) -> object:
    """Parse one YAML document. With several documents, the last one is returned."""
    docs = load_all(text)
    return docs[-1] if docs else None


def load_all(text: str) -> list[object]:
    docs: list[list[_Line]] = [[]]
    raw_lines = text.lstrip("\ufeff").splitlines()
    i = 0
    while i < len(raw_lines):
        number = i + 1
        line = raw_lines[i].rstrip("\r").rstrip()
        i += 1
        if line in ("---", "..."):
            docs.append([])
            continue
        stripped = line.lstrip(" ")
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("\t"):
            raise ValueError(f"line {number}: tabs are not allowed for indentation")
        indent = len(line) - len(stripped)
        block = _block_header(stripped)
        if block is not None:
            # Read a block scalar here, before comment stripping, so lines starting
            # with '#' inside it are kept as text. It becomes a quoted scalar.
            key, header = block
            body: list[str] = []
            while i < len(raw_lines):
                raw = raw_lines[i].rstrip("\r")
                if raw.strip() and len(raw) - len(raw.lstrip(" ")) <= indent:
                    break
                body.append(raw)
                i += 1
            stripped = f"{key}: {json.dumps(_block_value(body, header))}"
        docs[-1].append(_Line(indent, stripped, number))
    out = []
    for lines in docs:
        if not lines:
            continue
        parser = _Parser(lines)
        value = parser.node(0, lines[0].indent)
        if parser.i != len(lines):
            line = lines[parser.i]
            raise ValueError(f"line {line.number}: unexpected indentation")
        out.append(value)
    return out


class _Parser:
    def __init__(self, lines: list[_Line]):
        self.lines = lines
        self.i = 0

    def node(self, i: int, indent: int) -> object:
        self.i = i
        if self.lines[i].text == "-" or self.lines[i].text.startswith("- "):
            return self.sequence(indent)
        return self.mapping(indent)

    def mapping(self, indent: int) -> dict:
        result: dict = {}
        lines = self.lines
        while self.i < len(lines) and lines[self.i].indent == indent:
            line = lines[self.i]
            if line.text == "-" or line.text.startswith("- "):
                raise ValueError(f"line {line.number}: sequence item inside a mapping")
            key, rest = _split_key(line.text, line.number)
            self.i += 1
            if rest.startswith("#"):
                rest = ""  # "key:  # comment" has an empty value
            if rest == "":
                nxt = lines[self.i] if self.i < len(lines) else None
                if nxt is not None and nxt.indent > indent:
                    value = self.node(self.i, nxt.indent)
                elif nxt is not None and nxt.indent == indent and (nxt.text == "-" or nxt.text.startswith("- ")):
                    value = self.sequence(indent)  # YAML allows "key:\n- item" at the same indent
                else:
                    value = None
            elif rest[0] in "\"'":
                value = self.quoted_continuation(rest, indent, line.number)
            else:
                value = _scalar_or_flow(rest, line.number)
            result[key] = value
        return result

    def sequence(self, indent: int) -> list:
        items: list = []
        lines = self.lines
        while self.i < len(lines) and lines[self.i].indent == indent and (
            lines[self.i].text == "-" or lines[self.i].text.startswith("- ")
        ):
            line = lines[self.i]
            rest = line.text[1:].lstrip(" ")
            if not rest:
                self.i += 1
                nxt = lines[self.i] if self.i < len(lines) else None
                items.append(self.node(self.i, nxt.indent) if nxt is not None and nxt.indent > indent else None)
                continue
            child_indent = indent + (len(line.text) - len(rest))
            if _looks_like_key(rest):
                # "- key: value" starts a mapping whose keys sit at child_indent.
                lines[self.i] = _Line(child_indent, rest, line.number)
                items.append(self.mapping(child_indent))
            else:
                items.append(_scalar_or_flow(rest, line.number))
                self.i += 1
        return items

    def quoted_continuation(self, text: str, indent: int, number: int) -> object:
        """A quoted scalar may continue over more-indented lines; line breaks fold to spaces."""
        while True:
            try:
                return _scalar_or_flow(text, number)
            except _Unterminated:
                if self.i >= len(self.lines) or self.lines[self.i].indent <= indent:
                    raise
                text += " " + self.lines[self.i].text
                self.i += 1


def _block_header(text: str) -> tuple[str, str] | None:
    """('key', '|') when the line opens a block scalar, else None."""
    if text.startswith("- "):
        return None
    try:
        key, rest = _split_key(text, 0)
    except ValueError:
        return None
    if not rest or not _BLOCK_INDICATOR.match(rest):
        return None
    quoted_key = json.dumps(key)
    return quoted_key, rest.split()[0]


def _block_value(body: list[str], header: str) -> str:
    lines = [ln.rstrip() for ln in body]
    while lines and not lines[-1].strip():
        lines.pop()
    content = [ln for ln in lines if ln.strip()]
    common = min((len(ln) - len(ln.lstrip(" ")) for ln in content), default=0)
    lines = [ln[common:] if ln.strip() else "" for ln in lines]
    if header.startswith("|"):
        value = "\n".join(lines)
    else:  # folded: single line breaks become spaces, blank lines become line breaks
        value, pending = "", ""
        for ln in lines:
            if not ln:
                pending += "\n"
            else:
                value += (pending or (" " if value else "")) + ln
                pending = ""
    if "-" in header:
        return value
    return value + "\n" if value else value


def _looks_like_key(text: str) -> bool:
    if text[0] in "\"'":
        try:
            _, end = _quoted(text, 0, 0)
        except ValueError:
            return False
        return text[end:].lstrip(" ").startswith(":")
    if text[0] in "[{":
        return False
    return ": " in text or text.endswith(":")


def _split_key(text: str, number: int) -> tuple[str, str]:
    if text[0] in "\"'":
        key, end = _quoted(text, 0, number)
        rest = text[end:].lstrip(" ")
        if not rest.startswith(":"):
            raise ValueError(f"line {number}: expected ':' after quoted key")
        return key, rest[1:].strip()
    idx = text.find(": ")
    if idx != -1:
        return text[:idx].rstrip(), text[idx + 2:].strip()
    if text.endswith(":"):
        return text[:-1].rstrip(), ""
    raise ValueError(f"line {number}: expected 'key: value'")


def _quoted(text: str, start: int, number: int) -> tuple[str, int]:
    """Read a quoted scalar starting at text[start]; return (value, index after it)."""
    quote = text[start]
    i = start + 1
    if quote == "'":
        out = []
        while i < len(text):
            if text[i] == "'":
                if i + 1 < len(text) and text[i + 1] == "'":
                    out.append("'")
                    i += 2
                    continue
                return "".join(out), i + 1
            out.append(text[i])
            i += 1
    else:
        out = []
        while i < len(text):
            ch = text[i]
            if ch == '"':
                value = "".join(out)
                # json.dumps output may carry surrogate pairs as two \u escapes
                return value.encode("utf-16", "surrogatepass").decode("utf-16"), i + 1
            if ch == "\\":
                if i + 1 >= len(text):
                    break
                esc = text[i + 1]
                if esc in _HEX_ESCAPES:
                    digits = text[i + 2:i + 2 + _HEX_ESCAPES[esc]]
                    if len(digits) != _HEX_ESCAPES[esc] or not all(c in "0123456789abcdefABCDEF" for c in digits):
                        raise ValueError(f"line {number}: bad \\{esc} escape")
                    out.append(chr(int(digits, 16)))
                    i += 2 + len(digits)
                    continue
                if esc not in _ESCAPES:
                    raise ValueError(f"line {number}: unsupported escape \\{esc}")
                out.append(_ESCAPES[esc])
                i += 2
                continue
            out.append(ch)
            i += 1
    raise _Unterminated(f"line {number}: unterminated quoted string")


def _scalar_or_flow(text: str, number: int) -> object:
    text = text.strip()
    if text[0] in "[{":
        value, end = _flow(text, 0, number)
        if text[end:].strip() and not text[end:].strip().startswith("#"):
            raise ValueError(f"line {number}: unexpected text after flow collection")
        return value
    if text[0] in "\"'":
        value, end = _quoted(text, 0, number)
        tail = text[end:].strip()
        if tail and not tail.startswith("#"):
            raise ValueError(f"line {number}: unexpected text after quoted value")
        return value
    hash_at = text.find(" #")
    if hash_at != -1:
        text = text[:hash_at].rstrip()
    if text[:1] in ("&", "*", "!"):
        raise ValueError(f"line {number}: anchors, aliases and tags are not supported")
    return None if text in ("", "~", "null") else text


def _flow(text: str, i: int, number: int) -> tuple[object, int]:
    """Parse a flow mapping or sequence starting at text[i]."""
    opener = text[i]
    closer = "}" if opener == "{" else "]"
    result: object = {} if opener == "{" else []
    i += 1
    while True:
        i = _skip_spaces(text, i)
        if i >= len(text):
            raise ValueError(f"line {number}: unterminated flow collection")
        if text[i] == closer:
            return result, i + 1
        item, i = _flow_item(text, i, number, stop=",:" + closer if opener == "{" else "," + closer)
        if opener == "{":
            i = _skip_spaces(text, i)
            value: object = None
            if i < len(text) and text[i] == ":":
                i = _skip_spaces(text, i + 1)
                if i < len(text) and text[i] not in ",}":
                    value, i = _flow_item(text, i, number, stop=",}")
            result[item] = value  # type: ignore[index]
        else:
            result.append(item)  # type: ignore[union-attr]
        i = _skip_spaces(text, i)
        if i < len(text) and text[i] == ",":
            i += 1
        elif i < len(text) and text[i] == closer:
            continue
        else:
            raise ValueError(f"line {number}: malformed flow collection")


def _flow_item(text: str, i: int, number: int, stop: str) -> tuple[object, int]:
    if text[i] in "[{":
        return _flow(text, i, number)
    if text[i] in "\"'":
        return _quoted(text, i, number)
    start = i
    while i < len(text):
        ch = text[i]
        if ch in stop and (ch != ":" or i + 1 >= len(text) or text[i + 1] in " ,}"):
            break
        i += 1
    return text[start:i].strip(), i


def _skip_spaces(text: str, i: int) -> int:
    while i < len(text) and text[i] == " ":
        i += 1
    return i
