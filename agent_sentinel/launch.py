"""What a server's launch command runs, and what is risky about it. Functions of the command's words.

    runner_package     the package a runner (npx, bunx, uvx, uv tool run, pipx run) fetches and runs
    unpinned_package   such a package run without an exact version
    advisory_findings  a package of advisories.py: malware (fail) or a known vulnerability (warn)
    typosquat_of       a package one edit away from a popular MCP package's name
    launch_risks       what is risky in the command itself: inline code (sh -c, powershell
                       -EncodedCommand, node -e, python -c), shell operators in arguments, sudo,
                       a download piped to a runner, a package from a git repository, a container
                       with host privileges or mounts or without an image digest, and arguments
                       that name credential files, a whole drive or the whole home folder
    launch_identity    what proxy --pin-server pins of a launch (pins.py): the program, the runner's
                       package as written, and the SHA-256 of the local script it starts

doctor (cli_doctor._launch_lines), clients, wrap and inspect report these;
none of them starts a program or touches the network. launch_identity reads
one local file, the script, which the proxy is about to start anyway.

Everything returned that holds text from a configuration is already
printable (textutil.printable).
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass

from . import advisories, home
from .advisories import NPM, PYPI
from .templates import CREDENTIAL_PATTERN
from .textutil import printable

# ---- the program a word names -----------------------------------------------------------------

_ENDINGS = (".exe", ".cmd", ".bat", ".ps1", ".com")


def program_name(word: str) -> str:
    """The name of a program, lowercase, without its folder or a Windows ending: "C:\\x\\NPX.CMD" -> "npx"."""
    name = os.path.basename(word.replace("\\", "/")).lower()
    for ending in _ENDINGS:
        if name.endswith(ending):
            return name[: -len(ending)]
    return name


# The file name of a Python (as wrapping._PYTHON reads it), without an ending.
_PYTHON = re.compile(r"(python|pypy|graalpy)[0-9.]*t?w?(d|_d|-dbg)?(-intel64)?|pyw?")

# ---- packages a runner fetches ----------------------------------------------------------------

_EXACT_VERSION = re.compile(r"v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?")
# Where a PyPI package's name ends in a requirement such as "pkg>=1.0" or "pkg[extra]".
_PYPI_NAME_END = re.compile(r"[=<>~!@ \[;]")
_NPX_VALUE_OPTIONS = frozenset({"-p", "--package", "-c", "--call", "--cache", "--registry", "--userconfig", "-w",
                                "--workspace", "--node-options"})
_UVX_VALUE_OPTIONS = frozenset({
    "--from", "--with", "--with-editable", "--with-requirements", "-p", "--python", "--index", "--index-url",
    "--extra-index-url", "--default-index", "--find-links", "-f", "--constraint", "-c", "--override",
    "--python-preference", "--refresh-package", "--reinstall-package", "--upgrade-package", "--cache-dir",
    "--directory", "--project", "--config-file", "--env-file", "--index-strategy", "--keyring-provider",
    "--resolution", "--prerelease", "--exclude-newer", "--link-mode", "--compile-bytecode",
})
_PIPX_VALUE_OPTIONS = frozenset({"--spec", "--python", "--index-url", "-i", "--pip-args", "--suffix"})
_GIT_SOURCES = ("git+", "git:", "github:", "gitlab:", "bitbucket:", "gist:")


@dataclass(frozen=True)
class PackageRef:
    """The package a runner fetches: as written (`spec`), its registry name and its exact version, if any."""

    runner: str  # "npx", "bunx", "uvx", "uv tool run", "pipx run"
    ecosystem: str  # advisories.NPM or advisories.PYPI
    spec: str  # as written: "mcp-remote@0.1.16", "mcp-server-git==2026.1.14"
    name: str  # npm: lowercase; PyPI: normalised (PEP 503); "" when it is no registry package
    version: str | None  # the exact version the spec pins, if it pins one
    source: str  # "registry", "git", "url" or "path"

    @property
    def written(self) -> str:
        """The runner and the spec, as one text: "npx mcp-remote@0.1.16"."""
        return f"{self.runner} {self.spec}"


def runner_package(words: list[str]) -> PackageRef | None:
    """The package an npx, bunx, uvx, uv tool run or pipx run command runs; None for any other command."""
    if not words:
        return None
    program = program_name(words[0])
    if program in ("npx", "bunx"):
        spec = _first_package(words[1:], _NPX_VALUE_OPTIONS, ("-p", "--package"))
        return _npm_ref(program, spec) if spec else None
    if program == "uvx" or (program == "uv" and words[1:3] == ["tool", "run"]):
        runner = "uvx" if program == "uvx" else "uv tool run"
        spec = _first_package(words[1:] if program == "uvx" else words[3:], _UVX_VALUE_OPTIONS, ("--from",))
        return _pypi_ref(runner, spec) if spec else None
    if program == "pipx" and words[1:2] == ["run"]:
        spec = _first_package(words[2:], _PIPX_VALUE_OPTIONS, ("--spec",))
        return _pypi_ref("pipx run", spec) if spec else None
    return None


def _first_package(args: list[str], value_options: frozenset[str], package_options: tuple[str, ...]) -> str | None:
    """The package a runner runs: the value of --package/--from, or else the first word that is not an option."""
    index = 0
    while index < len(args):
        word = args[index]
        name, equals, value = word.partition("=")
        if name in package_options:
            return value if equals else (args[index + 1] if index + 1 < len(args) else None)
        if word == "--":
            return args[index + 1] if index + 1 < len(args) else None
        if equals and name in value_options:
            pass
        elif word in value_options:
            index += 1
        elif not word.startswith("-"):
            return word
        index += 1
    return None


def _npm_ref(runner: str, spec: str) -> PackageRef:
    lowered = spec.lower()
    if lowered.startswith(_GIT_SOURCES) or ("/" in spec and not spec.startswith("@") and ":" not in spec
                                            and not spec.startswith((".", "/", "~"))):
        return PackageRef(runner, NPM, spec, "", None, "git")  # "user/repo" is a GitHub repository to npm
    if lowered.startswith(("http:", "https:")):
        return PackageRef(runner, NPM, spec, "", None, "url")
    if spec.startswith((".", "/", "~")) or ":" in spec or "\\" in spec:
        return PackageRef(runner, NPM, spec, "", None, "path")
    at = spec.find("@", 1)
    name = (spec if at == -1 else spec[:at]).lower()
    version = spec[at + 1:] if at != -1 and _EXACT_VERSION.fullmatch(spec[at + 1:]) else None
    return PackageRef(runner, NPM, spec, name, version, "registry")


def _pypi_ref(runner: str, spec: str) -> PackageRef:
    lowered = spec.lower()
    if lowered.startswith("git+") or " @ git+" in lowered or "@git+" in lowered:
        return PackageRef(runner, PYPI, spec, "", None, "git")
    if "://" in spec:
        return PackageRef(runner, PYPI, spec, "", None, "url")
    if spec.startswith((".", "/", "~")) or "\\" in spec:
        return PackageRef(runner, PYPI, spec, "", None, "path")
    name = pypi_name(_PYPI_NAME_END.split(spec, maxsplit=1)[0])
    version = None
    if "==" in spec and _EXACT_VERSION.fullmatch(spec.split("==", 1)[1].strip()):
        version = spec.split("==", 1)[1].strip()
    elif "==" not in spec and "@" in spec and _EXACT_VERSION.fullmatch(spec.split("@", 1)[1].strip()):
        version = spec.split("@", 1)[1].strip()  # uv's "package@1.2.3"
    return PackageRef(runner, PYPI, spec, name, version, "registry")


def pypi_name(name: str) -> str:
    """A PyPI name as the index compares it (PEP 503): lowercase, each run of "-", "_" and "." one "-"."""
    return re.sub(r"[-_.]+", "-", name).lower()


def unpinned_package(words: list[str]) -> tuple[str, str] | None:
    """(package, how to pin it) when a runner runs a registry package without an exact version; else None."""
    ref = runner_package(words)
    if ref is None or ref.source != "registry" or ref.version is not None:
        return None
    if ref.ecosystem == NPM:
        at = ref.spec.find("@", 1)
        return ref.spec, f"{ref.spec if at == -1 else ref.spec[:at]}@1.2.3"
    return ref.spec, _PYPI_NAME_END.split(ref.spec, maxsplit=1)[0] + "==1.2.3"


# ---- advisories and typosquats ----------------------------------------------------------------

_VERSION_PARTS = re.compile(r"v?([0-9]{1,18}(?:\.[0-9]{1,18}){0,7})(.*)", re.DOTALL)
_NOT_A_PRE_RELEASE = ("+", ".post", "-post", "post")


def _version_key(text: str, length: int) -> tuple[tuple[int, ...], int] | None:
    """A version as something to compare: its numbers (padded to `length`), then 0 for a pre-release, else 1."""
    found = _VERSION_PARTS.fullmatch(text.strip())
    if found is None:
        return None
    numbers = tuple(int(part) for part in found.group(1).split("."))
    rest = found.group(2)
    pre_release = bool(rest) and not rest.lower().startswith(_NOT_A_PRE_RELEASE)
    return numbers + (0,) * (length - len(numbers)), 0 if pre_release else 1


def version_before(version: str, bound: str) -> bool | None:
    """Whether `version` comes before `bound` (1.0.15 before 1.0.16, 1.0.16-rc.1 too); None when it cannot be read."""
    length = 8
    ours, theirs = _version_key(version, length), _version_key(bound, length)
    if ours is None or theirs is None:
        return None
    return ours < theirs


def _same_package(ref: PackageRef, advisory: advisories.Advisory) -> bool:
    wanted = advisory.name.lower() if advisory.ecosystem == NPM else pypi_name(advisory.name)
    return ref.source == "registry" and ref.ecosystem == advisory.ecosystem and ref.name == wanted


def advisory_findings(ref: PackageRef) -> list[tuple[str, str]]:
    """("fail" or "warn", what to say) for each advisory of advisories.py that concerns this package."""
    found = []
    shown = printable(ref.written, limit=200)
    for advisory in advisories.MALICIOUS:
        if not _same_package(ref, advisory):
            continue
        before = version_before(ref.version, advisory.first_bad) if ref.version else None
        if before:
            found.append(("warn", f"{shown}: {advisory.summary} ({advisory.ids}; {advisory.source}). This version "
                                  "is older than the malicious ones, but comes from the same place: remove it"))
        else:
            how = "is a malicious version" if ref.version else "does not pin an exact version, so it may fetch one"
            found.append(("fail", f"{shown} {how}: {advisory.summary} ({advisory.ids}; {advisory.source}). "
                                  "Remove this server, and treat what it could reach as exposed"))
    for advisory in advisories.VULNERABLE:
        if _same_package(ref, advisory) and ref.version and version_before(ref.version, advisory.fixed or ""):
            found.append(("warn", f"{shown} has a known vulnerability, fixed in {advisory.fixed}: {advisory.summary} "
                                  f"({advisory.ids}; {advisory.source}). Update it to {advisory.fixed} or later"))
    return found


def within_one_edit(one: str, other: str) -> bool:
    """Whether two different texts are one edit apart: a letter added, left out or changed, or two adjacent swapped."""
    if one == other or abs(len(one) - len(other)) > 1:
        return False
    if len(one) == len(other):
        differ = [index for index in range(len(one)) if one[index] != other[index]]
        if len(differ) == 1:
            return True
        return (len(differ) == 2 and differ[1] == differ[0] + 1
                and one[differ[0]] == other[differ[1]] and one[differ[1]] == other[differ[0]])
    shorter, longer = (one, other) if len(one) < len(other) else (other, one)
    index = 0
    while index < len(shorter) and shorter[index] == longer[index]:
        index += 1
    return shorter[index:] == longer[index + 1:]


def typosquat_of(ref: PackageRef) -> str | None:
    """The popular package (advisories.POPULAR) whose name this one imitates, one edit away; None otherwise."""
    if ref.source != "registry" or len(ref.name) < advisories.MIN_TYPOSQUAT_CHARS:
        return None
    popular = advisories.POPULAR.get(ref.ecosystem, ())
    if ref.name in popular or ref.name in advisories.LOOKALIKES_OK.get(ref.ecosystem, frozenset()):
        return None
    return next((name for name in popular if within_one_edit(ref.name, name)), None)


# ---- what is risky in the command itself --------------------------------------------------------

_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "csh", "tcsh", "ash", "busybox"})
_POWERSHELL = frozenset({"powershell", "pwsh", "powershell_ise"})
_NODE = frozenset({"node", "nodejs", "bun"})
_ELEVATE = frozenset({"sudo", "doas", "runas", "pkexec", "gsudo"})
_CONTAINER = frozenset({"docker", "podman", "nerdctl"})
_SHELL_OPERATORS = ("&&", "||", ";", "|")
_ELEVATE_IN_TEXT = re.compile(r"(?:^|[\s;&|(`'\"])(sudo|doas|runas|pkexec|gsudo)(?:\.exe)?(?:\s|$)", re.IGNORECASE)
_DOWNLOADER = re.compile(r"\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|"
                         r"start-bitstransfer|certutil|bitsadmin)\b", re.IGNORECASE)
_RUNNER_AT_START = re.compile(r"\s*(?:sudo\s+)?(sh|bash|zsh|dash|ksh|fish|python[0-9.]*|py|node|perl|ruby|php|iex|"
                              r"invoke-expression|pwsh|powershell|cmd)\b", re.IGNORECASE)
_EVALUATOR = re.compile(r"\b(iex|invoke-expression)\b", re.IGNORECASE)
_SUBSHELL_DOWNLOAD = re.compile(r"(?:\$\(|<\(|`)\s*(curl|wget)\b", re.IGNORECASE)
_CREDENTIAL = re.compile(CREDENTIAL_PATTERN, re.IGNORECASE)
_DRIVE_ROOT = re.compile(r"[A-Za-z]:[\\/]?|[\\/]{1,2}|\\\\\?\\[A-Za-z]:\\?")
_HOME_WORDS = frozenset({"~", "~/", "~\\", "$home", "${home}", "%userprofile%", "%homepath%", "$env:userprofile"})
# The options of `docker run` (and podman's) that take a value, so that the image is found after them.
_CONTAINER_VALUE_OPTIONS = frozenset({
    "-v", "--volume", "-e", "--env", "--env-file", "-p", "--publish", "--name", "--network", "--net", "--mount",
    "-w", "--workdir", "-u", "--user", "--entrypoint", "--pid", "--ipc", "--uts", "--userns", "--cgroupns", "-l",
    "--label", "--label-file", "--cap-add", "--cap-drop", "--device", "--add-host", "--platform", "--pull",
    "--restart", "-m", "--memory", "--memory-swap", "--cpus", "--cpu-shares", "--cpuset-cpus", "-h", "--hostname",
    "--dns", "--dns-search", "--security-opt", "--tmpfs", "--ulimit", "--log-driver", "--log-opt", "--runtime",
    "--gpus", "--shm-size", "--stop-signal", "--stop-timeout", "--cidfile", "--volumes-from", "--expose", "--link",
    "--health-cmd", "--mac-address", "--ip", "--ip6", "-a", "--attach", "--group-add", "--isolation",
    "--network-alias", "--annotation", "--sysctl", "--device-cgroup-rule", "--storage-opt", "--domainname",
})
# How many words of one command are looked at, how many options after an interpreter (no real one has more),
# and how many risks are reported for it.
MAX_WORDS_LINTED = 4096
MAX_OPTIONS_SCANNED = 64
MAX_RISKS = 12


def launch_risks(words: list[str], user_home: str | None = None) -> list[str]:
    """What is risky about a launch command, each as a short printable phrase; empty when nothing is.

    `user_home`: the user's own folder, to recognise an argument that names
    it whole (default: this user's, from the environment).
    """
    words = words[:MAX_WORDS_LINTED]
    if user_home is None:
        folder = home.user_folder()
        user_home = str(folder) if folder is not None else None
    risks: list[str] = []
    risks += _inline_code(words)
    risks += _shell_operators(words[1:])
    risks += _elevation(words)
    if _piped_download(" ".join(words)):
        risks.append("downloads something and runs it (a download piped to a shell or interpreter)")
    risks += _package_from_git(words)
    risks += _container_risks(words, user_home)
    risks += _sensitive_arguments(words[1:], user_home)
    return list(dict.fromkeys(risks))[:MAX_RISKS]


def _inline_code(words: list[str]) -> list[str]:
    """Interpreters given code on the command line: sh -c, cmd /c, powershell -Command, node -e, python -c."""
    found = []
    for index, word in enumerate(words):
        program = program_name(word)
        options = words[index + 1:index + 1 + MAX_OPTIONS_SCANNED]
        flag = None
        if program in _SHELLS:
            flag = _first_option(options, lambda option: not option.startswith("--") and option[1:].isalpha()
                                 and "c" in option[1:])
        elif program == "cmd":
            flag = _first_option(options, lambda option: option[:2].lower() in ("/c", "/k", "/r"), prefixes=("/",))
        elif program in _POWERSHELL:
            flag = _powershell_inline(program, options)
        elif program in _NODE:
            flag = _first_option(options, lambda option: option.split("=", 1)[0] in ("-e", "--eval", "-p", "--print"),
                                 values=_NODE_VALUE_OPTIONS)
        elif program == "deno" and options[:1] == ["eval"]:
            flag = "eval"
        elif _PYTHON.fullmatch(program):
            flag = _first_option(options, lambda option: not option.startswith("--") and option[1:].isalpha()
                                 and "c" in option[1:], values=_PYTHON_VALUE_OPTIONS, stops=("-m",))
        if flag is not None:
            found.append(f"runs code written on the command line ({printable(program, limit=40)} "
                         f"{printable(flag, limit=40)})")
    return found


def _first_option(options: list[str], wanted, prefixes: tuple[str, ...] = ("-",), values: tuple[str, ...] = (),
                  stops: tuple[str, ...] = ()) -> str | None:
    """The first option of an interpreter that `wanted` accepts, looked for before its first word that is no option.

    `values`: the options that take the next word as their value; `stops`:
    options after which the rest belongs to something else (python -m).
    """
    index = 0
    while index < len(options):
        option = options[index]
        if not option.startswith(prefixes) or option in ("-", "--"):
            return None
        if wanted(option):
            return option
        if option in stops:
            return None
        index += 2 if option in values else 1
    return None


# PowerShell parameters that take a value, and the short names it also takes for them.
_POWERSHELL_VALUE_PARAMETERS = ("executionpolicy", "windowstyle", "version", "inputformat", "outputformat",
                                "psconsolefile", "configurationname", "configurationfile", "workingdirectory",
                                "settingsfile", "custompipename")
_POWERSHELL_VALUE_ALIASES = frozenset({"ep", "ex", "w", "v", "if", "of", "o", "wd"})


def _powershell_inline(program: str, options: list[str]) -> str | None:
    """-Command, -EncodedCommand or -CommandWithArgs (or a shortening PowerShell takes for them: -c, -enc, -ec, -e).

    Windows PowerShell (powershell.exe) also runs its first plain argument
    as a command; PowerShell 7 (pwsh) runs it as a script file.
    """
    index = 0
    while index < len(options):
        option = options[index]
        if not option.startswith(("-", "/")):
            return option if program != "pwsh" and not option.lower().endswith(".ps1") else None
        name = option.lstrip("-/").lower().split(":", 1)[0]
        if name in ("c", "e", "ec", "cwa") or (len(name) >= 2 and any(
                full.startswith(name) for full in ("command", "encodedcommand", "commandwithargs"))):
            return option
        if name in ("f", "file") or (len(name) >= 2 and "file".startswith(name)):
            return None
        takes_value = name in _POWERSHELL_VALUE_ALIASES or (
            len(name) >= 2 and any(full.startswith(name) for full in _POWERSHELL_VALUE_PARAMETERS))
        index += 2 if takes_value else 1
    return None


def _shell_operators(args: list[str]) -> list[str]:
    for arg in args:
        for operator in _SHELL_OPERATORS:
            if operator in arg:
                return [f"has the shell operator {operator!r} in an argument (a shell would run what follows it)"]
    return []


def _elevation(words: list[str]) -> list[str]:
    for word in words:
        program = program_name(word)
        found = program if program in _ELEVATE else None
        if found is None:
            match = _ELEVATE_IN_TEXT.search(word)
            found = match.group(1).lower() if match else None
        if found is not None:
            return [f"runs with raised privileges ({found})"]
    return []


def _piped_download(text: str) -> bool:
    """Whether a command downloads something and hands it to a runner: curl ... | sh, iex (iwr ...), $(curl ...).

    Split at each "|", so the check stays linear however long the text is.
    """
    parts = text.split("|")
    for left, right in zip(parts, parts[1:]):
        if _DOWNLOADER.search(left) and _RUNNER_AT_START.match(right):
            return True
    return bool((_EVALUATOR.search(text) and _DOWNLOADER.search(text)) or _SUBSHELL_DOWNLOAD.search(text))


def _package_from_git(words: list[str]) -> list[str]:
    ref = runner_package(words)
    if ref is not None and ref.source in ("git", "url"):
        return [f"runs a package straight from a git repository or a web address, unreviewed and unpinned "
                f"({printable(ref.written, limit=120)})"]
    if program_name(words[0]) in ("uvx", "uv", "pipx") and any(word.lower().startswith("git+") for word in words[1:]):
        return ["installs a package straight from a git repository (git+...), unreviewed and unpinned"]
    return []


def _container_risks(words: list[str], user_home: str | None) -> list[str]:
    """docker/podman run with --privileged, the host's root or home folder mounted, host namespaces, no image digest."""
    for index, word in enumerate(words):
        if program_name(word) not in _CONTAINER:
            continue
        rest = words[index + 1:]
        if rest[:1] == ["container"]:
            rest = rest[1:]
        if rest[:1] != ["run"]:
            return []
        return _run_options(rest[1:], user_home)
    return []


def _run_options(args: list[str], user_home: str | None) -> list[str]:
    risks, index, image = [], 0, None
    while index < len(args):
        word = args[index]
        if not word.startswith("-") or word == "--":
            image = args[index + 1] if word == "--" and index + 1 < len(args) else (None if word == "--" else word)
            break
        name, equals, value = word.partition("=")
        if not equals and name in _CONTAINER_VALUE_OPTIONS:
            value = args[index + 1] if index + 1 < len(args) else ""
            index += 1
        elif not equals and name[:2] == "-v" and len(name) > 2:  # -v/:/host
            name, value = "-v", name[2:]
        index += 1
        if name == "--privileged" and value.lower() not in ("false", "0"):
            risks.append("runs a container with --privileged (it has the run of the host)")
        elif name in ("--network", "--net", "--pid", "--ipc", "--uts", "--userns") and value.lower() == "host":
            risks.append(f"shares the host's {name.lstrip('-')} with the container ({name} host)")
        elif name in ("-v", "--volume", "--mount"):
            source = _mount_source(value) if name == "--mount" else _volume_source(value)
            what = _whole_folder(source, user_home) if source else None
            if what:
                risks.append(f"mounts {what} into the container ({printable(name, limit=20)} "
                             f"{printable(value, limit=120)})")
    if image is not None and "@sha256:" not in image.lower():
        risks.append(f"runs the image {printable(image, limit=120)} by a tag, not pinned by digest (@sha256:...): a "
                     "new image can be pushed under the same tag")
    return risks


def _volume_source(value: str) -> str:
    """The host side of a -v value: "/:/host" -> "/", "C:\\:/host" -> "C:\\"."""
    if re.match(r"[A-Za-z]:[\\/:]", value) or re.fullmatch(r"[A-Za-z]:", value):
        rest = value[2:]
        cut = rest.find(":")
        return value if cut == -1 else value[: 2 + cut]
    return value.split(":", 1)[0]


def _mount_source(value: str) -> str:
    """The host side of a --mount value: "type=bind,source=/,target=/host" -> "/"."""
    for part in value.split(","):
        key, _, found = part.partition("=")
        if key.strip().lower() in ("source", "src"):
            return found.strip()
    return ""


def _whole_folder(value: str, user_home: str | None) -> str | None:
    """"the whole drive" or "the whole home folder" when a path names one of them; None otherwise."""
    text = value.strip().strip("\"'")
    if not text:
        return None
    if _DRIVE_ROOT.fullmatch(text):
        return "a whole drive (the root folder)"
    if text.lower() in _HOME_WORDS:
        return "the whole home folder"
    if user_home and (text.startswith("~") or home.is_absolute(text)):
        expanded = os.path.expanduser(text)
        if os.path.normcase(os.path.normpath(expanded)) == os.path.normcase(os.path.normpath(user_home)):
            return "the whole home folder"
    return None


def _sensitive_arguments(args: list[str], user_home: str | None) -> list[str]:
    found = []
    for arg in args:
        value = arg.split("=", 1)[1] if arg.startswith("-") and "=" in arg else arg
        if _CREDENTIAL.search(arg):
            found.append(f"names a credential or client configuration file in an argument "
                         f"({printable(arg, limit=120)})")
        whole = _whole_folder(value, user_home)
        if whole:
            found.append(f"gives the server {whole} in an argument ({printable(arg, limit=120)})")
    return found


# ---- what proxy --pin-server pins ----------------------------------------------------------------

LAUNCH_FIELDS = ("executable", "package", "script", "script_sha256")
# The largest script (or program) whose SHA-256 is taken; a larger one is pinned by its path only.
MAX_HASHED_BYTES = 64 * 1024 * 1024
_SCRIPT_RUNNERS = frozenset({"node", "nodejs", "bun", "deno", "ruby", "perl", "php", "bash", "sh", "zsh", "dash",
                             "ksh", "rscript", "lua", "tsx", "ts-node"})
_PYTHON_VALUE_OPTIONS = ("-X", "-W")
# Launchers whose own file says nothing of what runs: package runners (their package is pinned by its spec),
# shells given a command, and container runtimes (an image is pinned by its digest, which doctor checks).
_NOT_PINNED_BY_FILE = frozenset({"npx", "bunx", "uvx", "uv", "pipx", "cmd", "java", *_CONTAINER})
_NODE_VALUE_OPTIONS = ("-r", "--require", "--import", "--loader", "--experimental-loader", "--env-file",
                       "--conditions", "-C", "--title", "--inspect-port")


def launch_target(executable: str, words: list[str], cwd: str | None = None) -> str | None:
    """The local file a launch command runs: the script an interpreter is given, or else the program itself.

    None for a package runner (npx, uvx: the package is pinned by its
    spec), for a Python started with -m or -c, and for inline code. A
    relative script is read against `cwd` (the proxy's current folder), as the
    interpreter will read it.
    """
    program = program_name(words[0])
    if runner_package(words) is not None or program in _NOT_PINNED_BY_FILE:
        return None
    args = words[1:MAX_WORDS_LINTED]
    script: str | None
    if _PYTHON.fullmatch(program):
        script = _first_plain_word(args, _PYTHON_VALUE_OPTIONS, stops=("-m", "-c"))
    elif program in _SCRIPT_RUNNERS:
        if program in ("deno", "bun") and args[:1] == ["run"]:
            args = args[1:]
        script = _first_plain_word(args, _NODE_VALUE_OPTIONS, stops=("-e", "--eval", "-p", "--print", "-c"))
    elif program in _POWERSHELL:
        script = next((args[index + 1] for index in range(len(args) - 1)
                       if args[index].lstrip("-/").lower() in ("file", "f")), None)
    else:
        return os.path.abspath(executable)
    if script is None:
        return None
    return os.path.abspath(os.path.join(cwd or os.getcwd(), os.path.expanduser(script)))


def _first_plain_word(args: list[str], value_options: tuple[str, ...], stops: tuple[str, ...]) -> str | None:
    index = 0
    while index < len(args):
        word = args[index]
        if word in stops or word.split("=", 1)[0] in stops:
            return None
        if not word.startswith("-") or word == "-":
            return None if word == "-" else word
        index += 2 if word in value_options else 1
    return None


def file_sha256(path: str) -> str | None:
    """The SHA-256 of an ordinary file of at most MAX_HASHED_BYTES; None when it is not one, or cannot be read."""
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > MAX_HASHED_BYTES:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            read = 0
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                read += len(chunk)
                if read > MAX_HASHED_BYTES:  # it grew while it was read
                    return None
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, ValueError):
        return None


def launch_identity(executable: str, words: list[str], cwd: str | None = None) -> dict[str, str | None]:
    """What --pin-server pins of a launch (LAUNCH_FIELDS): the program found, the runner's package as
    written, and the local script with its SHA-256 (None for each that does not apply)."""
    ref = runner_package(words)
    script = launch_target(executable, words, cwd)
    return {
        "executable": os.path.abspath(executable),
        "package": ref.written if ref is not None else None,
        "script": script,
        "script_sha256": file_sha256(script) if script else None,
    }
