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
from dataclasses import dataclass


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
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\r").rstrip()
        if line in ("---", "..."):
            docs.append([])
            continue
        stripped = line.lstrip(" ")
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("\t"):
            raise ValueError(f"line {number}: tabs are not allowed for indentation")
        docs[-1].append(_Line(len(line) - len(stripped), stripped, number))
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
            if rest == "":
                nxt = lines[self.i] if self.i < len(lines) else None
                if nxt is not None and nxt.indent > indent:
                    value = self.node(self.i, nxt.indent)
                elif nxt is not None and nxt.indent == indent and (nxt.text == "-" or nxt.text.startswith("- ")):
                    value = self.sequence(indent)  # YAML allows "key:\n- item" at the same indent
                else:
                    value = None
            elif rest[0] in "|>":
                value = self.block_scalar(indent, rest)
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

    def block_scalar(self, indent: int, header: str) -> str:
        parts: list[str] = []
        while self.i < len(self.lines) and self.lines[self.i].indent > indent:
            parts.append(self.lines[self.i].text)
            self.i += 1
        joiner = "\n" if header.startswith("|") else " "
        return joiner.join(parts)


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
        while i < len(text):
            if text[i] == "\\":
                i += 2
                continue
            if text[i] == '"':
                raw = text[start:i + 1]
                try:
                    return json.loads(raw), i + 1
                except ValueError as exc:
                    raise ValueError(f"line {number}: unsupported escape in {raw}") from exc
            i += 1
    raise ValueError(f"line {number}: unterminated quoted string")


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
