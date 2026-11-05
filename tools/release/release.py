#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Единый релизный конвейер XIO.

Один скрипт на весь путь выпуска:

  1. артефакты — либо собираются на Debian по SSH (``--ssh``), либо берутся готовыми
     из каталога (``--dir``);
  2. подпись — ``apksigner verify --verbose --print-certs``, сертификат
     ``e4e81b12…c9671`` (полный SHA-256 в константе ``CERT_SHA256``);
  3. ``SHA256SUMS-<ver>.txt`` — пересчитывается по файлам, всегда LF;
  4. полнота — ровно 9 файлов выпуска (Windows ZIP может быть от другой версии);
  5. публикация — GitHub Release через API: create/update релиза, upload новых
     ассетов, delete заменяемых и лишних (по имени);
  6. анонимная проверка — каждый ассет скачивается без токена и сверяется
     по sha256 и размеру;
  7. отчёт и код возврата: 0 — всё совпало, 1 — любое расхождение.

Зависимости: только стандартная библиотека Python 3.8+. Внешние бинарники:
``apksigner`` (Android build-tools), ``ssh``/``scp`` (только для ``--ssh``).

Примеры:

    # локальная проверка без публикации
    python3 tools/release/release.py --tag v0.24.2 --dir releases/0.24.2 --dry-run

    # собрать Ubuntu-пакеты на Debian и выпустить
    python3 tools/release/release.py --tag v0.24.2 --ssh debian17 \
        --remote-repo /root/xio-linux --notes-file docs/release-notes-0.24.2.md

    # только скачать ассеты и сверить с локальными суммами
    python3 tools/release/release.py --tag v0.24.2 --dir releases/0.24.2 --verify-only

Коды возврата: 0 — успех, 1 — расхождение/ошибка, 2 — ошибка аргументов (argparse).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# --- Константы выпуска -------------------------------------------------------

#: Полный SHA-256 сертификата подписи XIO (совпадает с короткой записью
#: ``e4e81b12…c9671`` из release notes и docs).
CERT_SHA256 = "e4e81b12ec90709133f5d2be4c4071ab83c55a764aa54dbfc7dce5b2bffc9671"
CERT_SHORT = "e4e81b12…c9671"

#: Ожидаемое число файлов в выпуске (без SHA256SUMS).
EXPECTED_ARTIFACTS = 9

#: Шаблоны имён артефактов. ``{v}`` — версия выпуска, ``{w}`` — версия Windows-сборки:
#: она может отличаться (в 0.24.2 лежит ZIP от 0.24.1, см. docs/release-process.ru.md).
ARTIFACT_TEMPLATES: Tuple[str, ...] = (
    "XIO-{v}-ubuntu-amd64.deb",
    "XIO-{v}-ubuntu-x64.tar.gz",
    "XIO-Client-{v}-android-arm64-v8a.apk",
    "XIO-Client-{v}-android-armeabi-v7a.apk",
    "XIO-Client-{v}-android-universal.apk",
    "XIO-Full-{v}-android-arm64-v8a.apk",
    "XIO-Full-{v}-android-armeabi-v7a.apk",
    "XIO-Full-{w}-windows-x64.zip",
    "xio-server-{v}.tar.gz",
)

#: Артефакты, которые собираются на Debian (для режима ``--ssh``).
LINUX_ARTIFACTS: Tuple[str, ...] = (
    "XIO-{v}-ubuntu-amd64.deb",
    "XIO-{v}-ubuntu-x64.tar.gz",
)

SUMS_TEMPLATE = "SHA256SUMS-{v}.txt"

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")

#: Любое имя ассета, которое относится к выпускам XIO (любой версии).
RELATED_ASSET_RE = re.compile(
    r"^(?:SHA256SUMS-\d+\.\d+\.\d+\.txt"
    r"|XIO-\d+\.\d+\.\d+-ubuntu-(?:amd64\.deb|x64\.tar\.gz)"
    r"|XIO-Client-\d+\.\d+\.\d+-android-(?:arm64-v8a|armeabi-v7a|universal|x86_64)\.apk"
    r"|XIO-Full-\d+\.\d+\.\d+-android-(?:arm64-v8a|armeabi-v7a|universal|x86_64)\.apk"
    r"|XIO-Full-\d+\.\d+\.\d+-windows-x64\.zip"
    r"|xio-server-\d+\.\d+\.\d+\.tar\.gz)$"
)

USER_AGENT = "xio-release/1.0 (+https://github.com/rukazax/xio_vpn)"


# --- Ошибки ------------------------------------------------------------------


class ReleaseError(RuntimeError):
    """Ошибка, при которой выпуск продолжать нельзя."""


class SumsError(ValueError):
    """Некорректный файл SHA256SUMS."""


# --- Версия и тег ------------------------------------------------------------


def normalize_version(tag: str) -> str:
    """``v0.24.2`` → ``0.24.2``; ``0.24.2`` остаётся как есть."""
    value = (tag or "").strip()
    if value[:1] in ("v", "V"):
        value = value[1:]
    if not VERSION_RE.match(value):
        raise ReleaseError(f"версия {tag!r} не в формате X.Y.Z")
    return value


def tag_for(version: str) -> str:
    return f"v{normalize_version(version)}"


# --- Имена артефактов --------------------------------------------------------


def expected_artifacts(version: str, windows_version: Optional[str] = None) -> List[str]:
    """Ожидаемые имена девяти файлов выпуска.

    По умолчанию Windows ZIP берётся той же версии; ``windows_version`` позволяет
    заранее ожидать другую версию (в 0.24.2 — 0.24.1).
    """
    v = normalize_version(version)
    w = normalize_version(windows_version) if windows_version else v
    return [template.format(v=v, w=w) for template in ARTIFACT_TEMPLATES]


def artifact_patterns(version: str) -> List[re.Pattern]:
    """Регэкспы, которым должно соответствовать имя каждого из девяти файлов."""
    v = normalize_version(version)
    patterns: List[re.Pattern] = []
    for template in ARTIFACT_TEMPLATES:
        if "{w}" in template:
            patterns.append(re.compile(re.escape(template.split("{w}")[0]) + r"\d+\.\d+\.\d+" + re.escape(template.split("{w}")[1])))
        else:
            patterns.append(re.compile(re.escape(template.format(v=v, w=v)) + r"\Z"))
    return patterns


def artifact_prefixes() -> Tuple[str, ...]:
    """Префиксы имён выпуска — чтобы отличить артефакт от постороннего файла."""
    return (
        "XIO-",
        "xio-server-",
        "SHA256SUMS-",
    )


def is_artifact_name(name: str) -> bool:
    return name.startswith(artifact_prefixes())


def is_release_asset(name: str) -> bool:
    """Ассет относится к какому-либо выпуску XIO (его можно заменять/удалять)."""
    return bool(RELATED_ASSET_RE.match(name))


def windows_version_of(name: str) -> Optional[str]:
    match = re.match(r"^XIO-Full-(\d+\.\d+\.\d+)-windows-x64\.zip$", name)
    return match.group(1) if match else None


def version_tuple(value: str) -> Tuple[int, int, int]:
    """Версия как кортеж чисел — чтобы сравнивать «ниже/выше», а не по строке."""
    major, minor, patch = normalize_version(value).split(".")
    return int(major), int(minor), int(patch)


def windows_version_warnings(windows_versions: Iterable[str], version: str) -> List[str]:
    """Предупреждения о Windows ZIP, собранном не той версии, что выпуск.

    Это **не ошибка** набора: Windows-пакет собирается только на Windows-хосте,
    поэтому в выпуске может лежать ZIP предыдущей версии (так вышло в 0.24.2,
    где лежит 0.24.1). Но забывать об этом нельзя, поэтому расхождение всегда
    попадает в отчёт отдельным блоком предупреждений и не меняет код возврата.
    """
    v = normalize_version(version)
    result: List[str] = []
    for windows in windows_versions:
        w = normalize_version(windows)
        if w == v:
            continue
        if version_tuple(w) < version_tuple(v):
            result.append(
                f"Windows ZIP от версии {w} — ниже версии выпуска {v}: пакет не пересобран "
                "(собирается только на Windows-хосте, см. docs/release-process.ru.md, раздел 3)"
            )
        else:
            result.append(
                f"Windows ZIP от версии {w} — выше версии выпуска {v}: проверьте, откуда взялся файл"
            )
    return result


def sums_name(version: str) -> str:
    return SUMS_TEMPLATE.format(v=normalize_version(version))


# --- Разбор и рендер SHA256SUMS ---------------------------------------------


@dataclass(frozen=True)
class SumEntry:
    sha256: str
    name: str

    @property
    def line(self) -> str:
        return f"{self.sha256}  {self.name}"


SUM_LINE_RE = re.compile(r"^(?P<sha>[0-9a-fA-F]{64})(?:[ \t]+\*?)(?P<name>[^\s].*?)\s*$")


def parse_sums(text: str) -> Dict[str, str]:
    """Разобрать ``sha256  имя`` в словарь ``имя → sha256``.

    Терпит CRLF, хвостовые пробелы, комментарии ``#`` и пустые строки;
    отвергает битые суммы, строки без имени и повторяющиеся имена.
    """
    result: Dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\r\n").strip()
        if not line or line.startswith("#"):
            continue
        match = SUM_LINE_RE.match(line)
        if not match:
            raise SumsError(f"строка {lineno}: ожидается '<sha256>  <имя>', получено {raw!r}")
        sha = match.group("sha").lower()
        name = match.group("name").strip()
        if "/" in name or "\\" in name:
            raise SumsError(f"строка {lineno}: имя не должно содержать путь: {name!r}")
        if name in result:
            raise SumsError(f"строка {lineno}: имя {name!r} встречается дважды")
        result[name] = sha
    return result


def render_sums(entries: Mapping[str, str]) -> str:
    """Канонический текст SHA256SUMS: сортировка по имени, только LF."""
    lines = [f"{sha.lower()}  {name}" for name, sha in sorted(entries.items())]
    return ("\n".join(lines) + "\n") if lines else ""


def entries_from_text(text: str) -> Dict[str, str]:
    return parse_sums(text)


def lines_without_crlf(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


# --- Хеши --------------------------------------------------------------------


def sha256_file(path: os.PathLike | str, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


def file_digest(path: os.PathLike | str) -> Tuple[str, int]:
    """(sha256, размер) одного файла."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def digest_problems(
    expected_sha: str,
    expected_size: Optional[int],
    actual_sha: str,
    actual_size: Optional[int],
) -> List[str]:
    """Чистая сверка digest/размера: список расхождений (пустой — всё совпало)."""
    problems: List[str] = []
    if (expected_sha or "").lower() != (actual_sha or "").lower():
        problems.append(f"sha256: ожидался {expected_sha}, получен {actual_sha}")
    if expected_size is not None and actual_size is not None and expected_size != actual_size:
        problems.append(f"размер: ожидался {expected_size} Б, получен {actual_size} Б")
    return problems


# --- План работы с ассетами релиза ------------------------------------------


@dataclass
class AssetPlan:
    """Что делать с ассетами в GitHub Release."""

    upload: List[str] = field(default_factory=list)
    replace: List[str] = field(default_factory=list)
    remove: List[str] = field(default_factory=list)
    keep: List[str] = field(default_factory=list)
    foreign: List[str] = field(default_factory=list)
    reasons: Dict[str, str] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return not (self.upload or self.replace or self.remove)


def asset_plan(
    local: Mapping[str, Tuple[str, int]],
    remote: Mapping[str, Tuple[Optional[str], Optional[int]]],
) -> AssetPlan:
    """Сопоставить локальные файлы с ассетами релиза по имени и digest.

    * имя есть только локально → ``upload``;
    * имя есть с обеих сторон, digest и размер совпали → ``keep``;
    * digest (или размер) расходится либо GitHub не отдал digest → ``replace``
      (ассет удаляется и загружается заново: GitHub не умеет заменять на месте);
    * имя есть только в релизе и похоже на ассет XIO → ``remove``;
    * имя есть только в релизе и не похоже на ассет XIO → ``foreign`` (не трогаем).
    """
    plan = AssetPlan()
    for name in sorted(local):
        expected_sha, expected_size = local[name]
        if name not in remote:
            plan.upload.append(name)
            plan.reasons[name] = "ассета нет в релизе"
            continue
        remote_sha, remote_size = remote[name]
        if remote_sha is None:
            plan.replace.append(name)
            plan.reasons[name] = "GitHub не отдал digest — перезалить и сверить"
            continue
        problems = digest_problems(expected_sha, expected_size, remote_sha, remote_size)
        if problems:
            plan.replace.append(name)
            plan.reasons[name] = "; ".join(problems)
        else:
            plan.keep.append(name)

    for name in sorted(remote):
        if name in local:
            continue
        if is_release_asset(name):
            plan.remove.append(name)
            plan.reasons[name] = "лишний ассет релиза"
        else:
            plan.foreign.append(name)
            plan.reasons[name] = "посторонний ассет — не трогаем"
    return plan


# --- Полнота выпуска ---------------------------------------------------------


@dataclass
class Inventory:
    version: str
    found: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    unexpected: List[str] = field(default_factory=list)
    windows_versions: List[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.missing and len(self.found) == EXPECTED_ARTIFACTS


def classify_artifacts(names: Iterable[str], version: str) -> Inventory:
    """Проверить, что в каталоге лежат ровно девять ожидаемых файлов выпуска."""
    v = normalize_version(version)
    inventory = Inventory(version=v)
    patterns = artifact_patterns(v)
    names = [name for name in names if not name.startswith(".")]
    matched: set[str] = set()
    for name in names:
        for index, pattern in enumerate(patterns):
            if pattern.match(name):
                matched.add(name)
                if index == ARTIFACT_TEMPLATES.index("XIO-Full-{w}-windows-x64.zip"):
                    windows = windows_version_of(name)
                    if windows and windows not in inventory.windows_versions:
                        inventory.windows_versions.append(windows)
                break
        else:
            if is_artifact_name(name):
                inventory.unexpected.append(name)
    inventory.found = sorted(matched)
    expected = expected_artifacts(v)
    # Windows ZIP сверяем по шаблону (версия может отличаться), остальные — по имени.
    for index, name in enumerate(expected):
        if name in matched:
            continue
        if "{w}" in ARTIFACT_TEMPLATES[index]:
            if inventory.windows_versions:
                continue
        inventory.missing.append(name)
    return inventory


# --- Подпись APK -------------------------------------------------------------


APKSIGNER_CERT_RE = re.compile(r"Signer #\d+ certificate SHA-256 digest:\s*([0-9a-fA-F]{64})")
APKSIGNER_V2_RE = re.compile(r"Verified using v2 scheme \(APK Signature Scheme v2\):\s*(true|false)")


def parse_apksigner_cert(output: str) -> List[str]:
    """Все SHA-256 сертификатов из вывода ``apksigner verify --print-certs``."""
    return [match.group(1).lower() for match in APKSIGNER_CERT_RE.finditer(output)]


def parse_apksigner_v2(output: str) -> Optional[bool]:
    match = APKSIGNER_V2_RE.search(output)
    return None if match is None else match.group(1) == "true"


def signature_problems(output: str, exit_code: int, expected_cert: str = CERT_SHA256) -> List[str]:
    """Проверить вывод apksigner: код, схема v2 и digest сертификата."""
    problems: List[str] = []
    if exit_code != 0:
        problems.append(f"apksigner verify вернул код {exit_code}")
    certs = parse_apksigner_cert(output)
    if not certs:
        problems.append("в выводе нет 'Signer #N certificate SHA-256 digest'")
    elif expected_cert.lower() not in [c.lower() for c in certs]:
        problems.append(
            f"сертификат не тот: ожидался {CERT_SHORT} ({expected_cert[:16]}…), "
            f"получено {', '.join(c[:16] + '…' for c in certs)}"
        )
    v2 = parse_apksigner_v2(output)
    if v2 is False:
        problems.append("APK подписан без схемы v2")
    return problems


def find_apksigner(explicit: Optional[str] = None) -> Optional[str]:
    """Найти apksigner: параметр → XIO_APKSIGNER → PATH → ANDROID_HOME/build-tools."""
    if explicit:
        return explicit
    env_value = os.environ.get("XIO_APKSIGNER")
    if env_value:
        return env_value
    for name in ("apksigner", "apksigner.bat"):
        found = shutil.which(name)
        if found:
            return found
    roots = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"), str(Path.home() / "Android" / "Sdk")]
    candidates: List[Path] = []
    for root in roots:
        if not root:
            continue
        build_tools = Path(root) / "build-tools"
        if build_tools.is_dir():
            candidates.extend(sorted(build_tools.iterdir(), reverse=True))
    for candidate in candidates:
        for name in ("apksigner.bat", "apksigner"):
            path = candidate / name
            if path.is_file():
                return str(path)
    return None


def apk_signature(path: Path, apksigner: Optional[str]) -> Tuple[Optional[str], List[str]]:
    """Запустить apksigner и вернуть (сертификат, расхождения)."""
    if not apksigner:
        return None, ["apksigner не найден: задайте --apksigner или ANDROID_HOME"]
    try:
        result = subprocess.run(
            [apksigner, "verify", "--verbose", "--print-certs", str(path)],
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (OSError, subprocess.SubprocessError) as error:  # pragma: no cover - среда
        return None, [f"apksigner не запустился: {error}"]
    output = (result.stdout or "") + (result.stderr or "")
    certs = parse_apksigner_cert(output)
    return (certs[0] if certs else None), signature_problems(output, result.returncode)


# --- GitHub API --------------------------------------------------------------


def default_token() -> Optional[str]:
    """Токен: GITHUB_TOKEN/GH_TOKEN → %USERPROFILE%\\.dsh\\secrets\\github.json."""
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(name)
        if value:
            return value.strip()
    secret = Path.home() / ".dsh" / "secrets" / "github.json"
    try:
        data = json.loads(secret.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    token = data.get("token") or data.get("access_token")
    return token.strip() if isinstance(token, str) and token.strip() else None


def default_repo() -> str:
    """Репозиторий из origin текущего каталога, иначе rukazax/xio_vpn."""
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"], capture_output=True, text=True, timeout=15
        )
        url = result.stdout.strip()
        match = re.search(r"github\.com[:/]+([^/]+)/([^/\s]+?)(?:\.git)?$", url)
        if match:
            return f"{match.group(1)}/{match.group(2)}"
    except (OSError, subprocess.SubprocessError):
        pass
    return "rukazax/xio_vpn"


class GitHub:
    """Минимальный клиент Releases API (stdlib, без зависимостей)."""

    def __init__(self, repo: str, token: str, timeout: int = 120) -> None:
        self.repo = repo
        self.token = token
        self.timeout = timeout
        self.api = "https://api.github.com"
        self.uploads = "https://uploads.github.com"

    # -- транспорт --
    def _open(self, request: urllib.request.Request) -> Tuple[int, bytes]:
        request.add_header("Accept", "application/vnd.github+json")
        request.add_header("X-GitHub-Api-Version", "2022-11-28")
        request.add_header("User-Agent", USER_AGENT)
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", "replace")
            if error.code == 404:
                return 404, body.encode()
            raise ReleaseError(f"GitHub API {request.get_method()} {request.full_url} → {error.code}: {body[:400]}") from error
        except urllib.error.URLError as error:
            raise ReleaseError(f"GitHub API недоступен: {error.reason}") from error

    def request(self, method: str, url: str, payload: Optional[dict] = None) -> Tuple[int, object]:
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
        request = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        status, body = self._open(request)
        if not body:
            return status, None
        try:
            return status, json.loads(body)
        except ValueError:
            return status, body.decode("utf-8", "replace")

    # -- релиз --
    def get_release(self, tag: str) -> Optional[dict]:
        status, body = self.request("GET", f"{self.api}/repos/{self.repo}/releases/tags/{urllib.parse.quote(tag)}")
        if status == 404:
            return None
        return body if isinstance(body, dict) else None

    def create_release(self, tag: str, name: str, body: str, prerelease: bool = False) -> dict:
        status, payload = self.request(
            "POST",
            f"{self.api}/repos/{self.repo}/releases",
            {"tag_name": tag, "name": name, "body": body, "draft": False, "prerelease": prerelease},
        )
        if not isinstance(payload, dict):
            raise ReleaseError(f"неожиданный ответ при создании релиза: {payload!r}")
        return payload

    def update_release(self, release_id: int, **fields: object) -> dict:
        status, payload = self.request("PATCH", f"{self.api}/repos/{self.repo}/releases/{release_id}", dict(fields))
        if not isinstance(payload, dict):
            raise ReleaseError(f"неожиданный ответ при обновлении релиза: {payload!r}")
        return payload

    # -- ассеты --
    def list_assets(self, release_id: int) -> List[dict]:
        assets: List[dict] = []
        page = 1
        while True:
            status, payload = self.request(
                "GET", f"{self.api}/repos/{self.repo}/releases/{release_id}/assets?per_page=100&page={page}"
            )
            if not isinstance(payload, list) or not payload:
                break
            assets.extend(payload)
            if len(payload) < 100:
                break
            page += 1
        return assets

    def upload_asset(self, release_id: int, name: str, path: Path) -> dict:
        url = (
            f"{self.uploads}/repos/{self.repo}/releases/{release_id}/assets"
            f"?name={urllib.parse.quote(name)}"
        )
        size = path.stat().st_size
        with open(path, "rb") as handle:
            request = urllib.request.Request(url, data=handle, method="POST")
            request.add_header("Content-Type", "application/octet-stream")
            request.add_header("Content-Length", str(size))
            status, body = self._open(request)
        if status not in (200, 201):
            raise ReleaseError(f"загрузка {name} вернула {status}")
        try:
            return json.loads(body)
        except ValueError as error:  # pragma: no cover - среда
            raise ReleaseError(f"неожиданный ответ при загрузке {name}") from error

    def delete_asset(self, asset_id: int) -> None:
        status, _ = self.request("DELETE", f"{self.api}/repos/{self.repo}/releases/assets/{asset_id}")
        if status not in (204, 200, 404):
            raise ReleaseError(f"удаление ассета {asset_id} вернуло {status}")


def remote_digest(asset: Mapping[str, object]) -> Optional[Tuple[Optional[str], Optional[int]]]:
    """(sha256, размер) ассета релиза; sha256 = None, если GitHub его не отдал."""
    size = asset.get("size")
    digest = asset.get("digest")
    sha: Optional[str] = None
    if isinstance(digest, str) and digest.startswith("sha256:"):
        sha = digest.split(":", 1)[1].lower()
    return sha, size if isinstance(size, int) else None


def remote_map(assets: Sequence[Mapping[str, object]]) -> Dict[str, Tuple[Optional[str], Optional[int]]]:
    result: Dict[str, Tuple[Optional[str], Optional[int]]] = {}
    for asset in assets:
        name = asset.get("name")
        if isinstance(name, str):
            result[name] = remote_digest(asset)
    return result


def asset_id_by_name(assets: Sequence[Mapping[str, object]]) -> Dict[str, int]:
    result: Dict[str, int] = {}
    for asset in assets:
        name, ident = asset.get("name"), asset.get("id")
        if isinstance(name, str) and isinstance(ident, int):
            result[name] = ident
    return result


# --- Анонимная сверка --------------------------------------------------------


def download_url(repo: str, tag: str, name: str) -> str:
    return f"https://github.com/{repo}/releases/download/{urllib.parse.quote(tag)}/{urllib.parse.quote(name)}"


def download_and_digest(url: str, destination: Path, timeout: int = 600, attempts: int = 3) -> Tuple[str, int]:
    """Скачать URL без токена и вернуть (sha256, размер).

    GitHub отдаёт ассет не сразу после upload, поэтому 404 повторяется с паузой.
    """
    last_error: Optional[Exception] = None
    for attempt in range(1, attempts + 1):
        try:
            return _download_once(url, destination, timeout)
        except urllib.error.HTTPError as error:
            last_error = error
            if error.code != 404 or attempt == attempts:
                break
            time.sleep(2 * attempt)
        except (urllib.error.URLError, OSError):
            raise
    assert last_error is not None
    raise last_error


def _download_once(url: str, destination: Path, timeout: int) -> Tuple[str, int]:
    request = urllib.request.Request(url, method="GET")
    request.add_header("User-Agent", USER_AGENT)
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(request, timeout=timeout) as response, open(destination, "wb") as handle:
        for block in iter(lambda: response.read(1 << 20), b""):
            digest.update(block)
            size += len(block)
            handle.write(block)
    return digest.hexdigest(), size


def verify_downloads(
    repo: str,
    tag: str,
    local: Mapping[str, Tuple[str, int]],
    tmpdir: Path,
    timeout: int = 600,
) -> List[Tuple[str, int, str, str, List[str]]]:
    """Скачать каждый ассет анонимно и сверить с локальным digest.

    Возвращает строки отчёта: (имя, размер, локальный sha, скачанный sha, расхождения).
    """
    rows: List[Tuple[str, int, str, str, List[str]]] = []
    for name in sorted(local):
        expected_sha, expected_size = local[name]
        target = tmpdir / name
        try:
            actual_sha, actual_size = download_and_digest(download_url(repo, tag, name), target, timeout=timeout)
        except (urllib.error.URLError, OSError, ReleaseError) as error:
            rows.append((name, expected_size, expected_sha, "—", [f"скачивание не удалось: {error}"]))
            continue
        problems = digest_problems(expected_sha, expected_size, actual_sha, actual_size)
        rows.append((name, actual_size, expected_sha, actual_sha, problems))
        try:
            target.unlink()
        except OSError:  # pragma: no cover - среда
            pass
    return rows


# --- SSH-сборка --------------------------------------------------------------


def ssh_target(args: argparse.Namespace) -> str:
    return f"{args.ssh_user}@{args.ssh}" if args.ssh_user else args.ssh


def ssh_argv(args: argparse.Namespace) -> List[str]:
    argv = ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={args.ssh_timeout}"]
    if args.ssh_key:
        argv += ["-i", args.ssh_key]
    return argv


def build_on_debian(args: argparse.Namespace, version: str, directory: Path) -> List[str]:
    """Собрать Linux-артефакты на Debian по SSH и забрать их в каталог релиза."""
    problems: List[str] = []
    host = ssh_target(args)
    remote_repo = args.remote_repo or "~/xio-linux"
    remote_out = args.remote_out or f"releases/{version}"
    command = args.ssh_cmd or f"cd {shlex.quote(remote_repo)} && sh tools/build-linux.sh"
    print(f"[ssh] {host}: {command}")
    result = subprocess.run(ssh_argv(args) + [host, command], text=True)
    if result.returncode != 0:
        return [f"удалённая сборка на {host} завершилась с кодом {result.returncode}"]
    directory.mkdir(parents=True, exist_ok=True)
    for template in LINUX_ARTIFACTS:
        name = template.format(v=version)
        remote_path = f"{remote_repo.rstrip('/')}/{remote_out}/{name}"
        local_path = directory / name
        scp = ["scp", "-q", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={args.ssh_timeout}"]
        if args.ssh_key:
            scp += ["-i", args.ssh_key]
        scp += [f"{host}:{remote_path}", str(local_path)]
        print(f"[ssh] scp {name}")
        copied = subprocess.run(scp, text=True)
        if copied.returncode != 0:
            problems.append(f"не удалось забрать {name} с {host}")
    return problems


# --- Каталог выпуска ---------------------------------------------------------


def collect_local(directory: Path) -> Dict[str, Tuple[str, int]]:
    """sha256 и размер всех файлов каталога (скрытые и подкаталоги игнорируются)."""
    local: Dict[str, Tuple[str, int]] = {}
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.name.startswith("."):
            continue
        local[path.name] = file_digest(path)
    return local


def ensure_sums(directory: Path, version: str, local: Mapping[str, Tuple[str, int]], dry_run: bool) -> Tuple[Optional[Path], List[str]]:
    """Пересчитать и (если нужно) записать SHA256SUMS-<ver>.txt; всегда LF."""
    name = sums_name(version)
    path = directory / name
    artifacts = {key: value[0] for key, value in local.items() if key != name}
    text = render_sums(artifacts)
    problems: List[str] = []
    current = path.read_bytes().decode("utf-8", "replace") if path.exists() else None
    normalized = lines_without_crlf(current) if current is not None else None
    has_crlf = current is not None and "\r" in current
    if has_crlf:
        problems.append(f"{name}: CRLF вместо LF")
    if normalized != text or has_crlf:
        if dry_run:
            print(f"[dry-run] {name} был бы перезаписан ({len(artifacts)} записей)")
        else:
            path.write_bytes(text.encode("utf-8"))
            print(f"[sums] записан {name} ({len(artifacts)} записей, LF)")
    else:
        print(f"[sums] {name} актуален ({len(artifacts)} записей, LF)")
    # Ассеты должны совпадать с суммами один в один.
    recorded = parse_sums(text) if text else {}
    for artifact, sha in recorded.items():
        if artifact not in local:
            problems.append(f"{name}: упоминает отсутствующий файл {artifact}")
        elif local[artifact][0] != sha:
            problems.append(f"{name}: sha256 для {artifact} не совпадает с файлом")
    return path, problems


# --- Отчёт -------------------------------------------------------------------


def human(size: int) -> str:
    value = float(size)
    for unit in ("Б", "КиБ", "МиБ", "ГиБ"):
        if value < 1024 or unit == "ГиБ":
            return f"{value:.1f} {unit}" if unit != "Б" else f"{int(value)} Б"
        value /= 1024
    return f"{size} Б"


def print_asset_table(rows: Sequence[Tuple[str, int, str, str, List[str]]]) -> None:
    print(f"{'ассет':58} {'размер':>12}  {'sha256 локально':16} {'sha256 в релизе':16} итог")
    for name, size, local_sha, remote_sha, problems in rows:
        verdict = "OK" if not problems else "FAIL"
        print(
            f"{name:58} {human(size):>12}  {local_sha[:16]:16} {remote_sha[:16]:16} {verdict}"
        )
        for problem in problems:
            print(f"{'':58} ↳ {problem}")


def print_plan(plan: AssetPlan) -> None:
    labels = (
        ("upload", "загрузить (нет в релизе)"),
        ("replace", "перезалить (digest/размер расходятся)"),
        ("remove", "удалить (лишнее в релизе)"),
        ("keep", "оставить (совпало)"),
        ("foreign", "не трогать (посторонний ассет)"),
    )
    for attribute, title in labels:
        names: List[str] = getattr(plan, attribute)
        if not names:
            continue
        print(f"  {title}: {len(names)}")
        for name in names:
            reason = plan.reasons.get(name, "")
            print(f"    - {name}" + (f" — {reason}" if reason else ""))


# --- main --------------------------------------------------------------------


def force_safe_output() -> None:
    """Не падать на русской консоли Windows (cp1251/cp866).

    В текстах есть «—», «→», «…», которых нет в legacy-кодовых страницах:
    без этой настройки ``print`` бросает UnicodeEncodeError и скрипт падает
    ещё до первой проверки. Кодировку консоли не меняем, только режим ошибок.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:  # pragma: no cover - среда
            continue
        try:
            reconfigure(errors="replace")
        except (ValueError, OSError):  # pragma: no cover - среда
            pass


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="release.py",
        description="Единый релизный конвейер XIO: артефакты → подпись → SHA256SUMS → GitHub Release → анонимная сверка.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Примеры:\n"
            "  python3 tools/release/release.py --tag v0.24.2 --dir releases/0.24.2 --dry-run\n"
            "  python3 tools/release/release.py --tag v0.24.2 --ssh debian17 --notes-file docs/release-notes-0.24.2.md\n"
            "  python3 tools/release/release.py --tag v0.24.2 --dir releases/0.24.2 --verify-only\n"
        ),
    )
    parser.add_argument("--tag", required=True, help="тег выпуска, например v0.24.2")
    parser.add_argument("--dir", help="каталог с готовыми артефактами (по умолчанию releases/<ver>)")
    parser.add_argument("--repo", help="владелец/репозиторий GitHub (по умолчанию из origin)")
    parser.add_argument("--dry-run", action="store_true", help="ничего не менять: только проверки и план")
    parser.add_argument("--verify-only", action="store_true", help="только скачать ассеты и сверить (без публикации)")
    parser.add_argument("--notes-file", help="файл с текстом релиза (Markdown)")
    parser.add_argument("--name", help="имя релиза (по умолчанию 'XIO <tag>')")
    parser.add_argument("--prerelease", action="store_true", help="пометить релиз как prerelease")
    parser.add_argument("--token", help="токен GitHub (иначе GITHUB_TOKEN или ~/.dsh/secrets/github.json)")
    parser.add_argument("--apksigner", help="путь к apksigner (иначе PATH/ANDROID_HOME)")
    parser.add_argument("--skip-signature", action="store_true", help="не проверять подпись APK (осознанно)")
    parser.add_argument("--windows-version", help="ожидаемая версия Windows ZIP, если она не равна версии выпуска")
    parser.add_argument("--timeout", type=int, default=600, help="таймаут скачивания ассета, секунд")
    parser.add_argument("--ssh", help="хост Debian для сборки Linux-артефактов")
    parser.add_argument("--ssh-user", help="пользователь SSH (по умолчанию из ~/.ssh/config)")
    parser.add_argument("--ssh-key", help="приватный ключ SSH")
    parser.add_argument("--ssh-timeout", type=int, default=20, help="ConnectTimeout для ssh/scp")
    parser.add_argument("--remote-repo", help="каталог репозитория на Debian")
    parser.add_argument("--remote-out", help="каталог артефактов на Debian (по умолчанию releases/<ver>)")
    parser.add_argument("--ssh-cmd", help="своя команда сборки вместо 'sh tools/build-linux.sh'")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    force_safe_output()
    args = parse_args(argv)
    try:
        version = normalize_version(args.tag)
    except ReleaseError as error:
        print(f"ОШИБКА: {error}", file=sys.stderr)
        return 1
    tag = tag_for(version)
    directory = Path(args.dir) if args.dir else Path("releases") / version
    repo = args.repo or default_repo()
    sums_problems: List[str] = []
    failures: List[str] = []

    print("=" * 78)
    print(f"XIO release {tag} | репозиторий {repo} | каталог {directory}")
    print(f"режим: {'dry-run' if args.dry_run else 'verify-only' if args.verify_only else 'публикация'}")
    print("=" * 78)

    # 1. Артефакты: сборка на Debian или готовые файлы.
    if args.ssh and not args.verify_only:
        ssh_errors = build_on_debian(args, version, directory)
        failures.extend(ssh_errors)
    if not directory.is_dir():
        print(f"ОШИБКА: каталога {directory} нет (соберите артефакты или передайте --dir)", file=sys.stderr)
        return 1

    # 2. Полнота набора.
    names = [path.name for path in directory.iterdir() if path.is_file()]
    inventory = classify_artifacts(names, version)
    print(f"\n[1/5] артефакты: {len(inventory.found)}/{EXPECTED_ARTIFACTS}")
    for name in inventory.found:
        print(f"  + {name} ({human((directory / name).stat().st_size)})")
    if inventory.missing:
        print("  отсутствуют:")
        for name in inventory.missing:
            print(f"  - {name}")
        failures.append(f"нет файлов выпуска: {', '.join(inventory.missing)}")
    if inventory.unexpected:
        others = [name for name in inventory.unexpected if name != sums_name(version)]
        if others:
            print("  посторонние файлы выпуска (не входят в 9):")
            for name in others:
                print(f"  ? {name}")
    warnings: List[str] = windows_version_warnings(inventory.windows_versions, version)
    for warning in warnings:
        print(f"  ! {warning}")

    # 3. Подпись APK.
    print("\n[2/5] подпись APK")
    apks = [name for name in inventory.found if name.endswith(".apk")]
    if not apks:
        print("  APK в наборе нет — проверять нечего")
    apksigner = find_apksigner(args.apksigner)
    if apks and args.skip_signature:
        print("  проверка отключена флагом --skip-signature")
    for name in apks:
        if args.skip_signature:
            break
        cert, problems = apk_signature(directory / name, apksigner)
        if problems:
            print(f"  FAIL {name}")
            for problem in problems:
                print(f"       {problem}")
            failures.extend(f"{name}: {problem}" for problem in problems)
        else:
            print(f"  OK   {name} — сертификат {CERT_SHORT}")

    # 4. SHA256SUMS.
    print("\n[3/5] SHA256SUMS")
    local = collect_local(directory)
    # В verify-only локальный каталог не трогаем: расхождение — это расхождение.
    _, sums_problems = ensure_sums(directory, version, local, args.dry_run or args.verify_only)
    for problem in sums_problems:
        print(f"  FAIL {problem}")
    failures.extend(sums_problems)
    local = collect_local(directory)

    # 5. План публикации.
    print(f"\n[4/5] GitHub Release {tag}")
    token = args.token or default_token()
    client: Optional[GitHub] = None
    release: Optional[dict] = None
    if not token:
        print("  токена нет (--token / GITHUB_TOKEN / ~/.dsh/secrets/github.json) — план без сети")
    else:
        client = GitHub(repo, token, timeout=args.timeout)
        try:
            release = client.get_release(tag)
        except ReleaseError as error:
            print(f"  FAIL {error}")
            failures.append(str(error))
    plan: Optional[AssetPlan] = None
    if release is not None:
        assets = client.list_assets(int(release["id"])) if client else []
        current = remote_map(assets)
        plan = asset_plan(local, current)
        print(f"  релиз существует: id={release['id']}, ассетов {len(assets)}")
        print_plan(plan)
    elif token:
        print("  релиза нет — будет создан")
        plan = asset_plan(local, {})

    if not args.dry_run and not args.verify_only and token and client is not None:
        body = Path(args.notes_file).read_text(encoding="utf-8") if args.notes_file else ""
        if release is None:
            release = client.create_release(tag, args.name or f"XIO {tag}", body, args.prerelease)
            print(f"  создан релиз id={release['id']}")
        elif body:
            client.update_release(int(release["id"]), body=body)
            print("  тело релиза обновлено из --notes-file")
        if plan is not None:
            assets = client.list_assets(int(release["id"]))
            ids = asset_id_by_name(assets)
            for name in plan.replace + plan.remove:
                if name in ids:
                    client.delete_asset(ids[name])
                    print(f"  удалён ассет {name}")
            # SHA256SUMS-<ver>.txt уже входит в local: ensure_sums записал его выше.
            for name in list(plan.upload) + list(plan.replace):
                if name not in local:
                    continue
                uploaded = client.upload_asset(int(release["id"]), name, directory / name)
                print(f"  загружен {name} ({uploaded.get('size')} Б)")

    # 6. Анонимная сверка.
    print("\n[5/5] анонимная сверка ассетов")
    rows: List[Tuple[str, int, str, str, List[str]]] = []
    if args.dry_run:
        print("  dry-run: скачивание не выполняется")
    elif not token and not args.verify_only:
        print("  без токена проверить релиз нельзя — пропущено")
    else:
        with tempfile.TemporaryDirectory(prefix="xio-release-") as tmp:
            rows = verify_downloads(repo, tag, local, Path(tmp), timeout=args.timeout)
        print_asset_table(rows)
        for name, _size, _local_sha, _remote_sha, problems in rows:
            failures.extend(f"{name}: {problem}" for problem in problems)

    # 7. Итог.
    print("\n" + "=" * 78)
    print(f"файлов выпуска: {len(inventory.found)}/{EXPECTED_ARTIFACTS}; ассетов в проверке: {len(rows)}")
    if failures:
        print(f"ИТОГ: FAIL — расхождений {len(failures)}")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    if warnings:
        print(f"ПРЕДУПРЕЖДЕНИЯ: {len(warnings)} — на код возврата не влияют")
        for warning in warnings:
            print(f"  ! {warning}")
    print("ИТОГ: OK — все проверки пройдены")
    return 0


if __name__ == "__main__":
    sys.exit(main())
