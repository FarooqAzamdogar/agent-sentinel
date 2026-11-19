"""`guard`: put the firewall around a tool function, keeping what agent frameworks read from it.

    firewall = Firewall(Policy.from_file("policy.json"), audit_path="audit.jsonl")

    @guard(firewall)
    def read_file(path: str, limit: int = 100) -> str:
        '''Read the start of a text file.'''
        ...

    read_file("notes.txt")      # checked as read_file(path="notes.txt", limit=100), run, its result scanned

Every call goes through `Firewall.run` (or `run_async` for an `async def`
tool): the secret guard, the policy, flow rules and rate limits; then the
function; then its result, or the text of an error it raises, is scanned
before it is returned. A blocked call raises BlockedError, whose text is
safe to hand to the model. With on_block="return", the decorated function
returns that text instead, for frameworks that pass a tool's return value
to the model and stop on an exception.

The positional and keyword arguments of a call are bound to the
function's parameters, defaults included, so the policy always sees every
argument by name, however the caller spelled the call. That is why the
function must name every parameter: one that takes *args or **kwargs, or a
positional-only parameter, is refused when it is decorated. For a method,
guard the bound method (`guard(firewall)(client.search)`), so that `self`
is not checked as an argument.

The decorated function keeps the original's name, docstring, signature and
type hints (functools.wraps, which sets __wrapped__; inspect.signature and
typing.get_type_hints follow it). Those are what frameworks that build a
tool from a function read to describe it to the model, so the guard goes
under the framework's decorator (see examples/langchain_guarded_tools.py).
A generator function is refused: what it yields would reach the agent
unchecked.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, TypeVar

from .firewall import BlockedError, Firewall

ON_BLOCK = ("raise", "return")

Tool = TypeVar("Tool", bound=Callable[..., Any])


def guard(firewall: Firewall, name: str | None = None, *, on_block: str = "raise") -> Callable[[Tool], Tool]:
    """A decorator that sends every call of a tool function through `firewall` (see the module docstring).

    name:     the tool's name for the policy and the audit log (default: the
              function's __name__)
    on_block: "raise" (BlockedError) or "return" (the text the model may read,
              which ends with the block's ref)
    """
    if not isinstance(firewall, Firewall):
        raise TypeError("guard() needs a Firewall: guard(firewall) or guard(firewall, name='tool_name')")
    if on_block not in ON_BLOCK:
        raise ValueError(f"on_block must be 'raise' or 'return', not {on_block!r}")
    if name is not None and (not isinstance(name, str) or not name.strip()):
        raise ValueError("name must be text that is not empty")

    def decorate(function: Tool) -> Tool:
        signature = _checked_signature(function)
        tool = name if name is not None else _name_of(function)
        if inspect.iscoroutinefunction(function):

            @functools.wraps(function)
            async def guarded_coroutine(*args: Any, **kwargs: Any) -> Any:
                arguments = _bound(signature, args, kwargs)
                try:
                    return await firewall.run_async(tool, arguments, function)
                except BlockedError as error:
                    if on_block == "return":
                        return str(error)
                    raise

            return guarded_coroutine  # type: ignore[return-value]

        @functools.wraps(function)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            arguments = _bound(signature, args, kwargs)
            try:
                return firewall.run(tool, arguments, function)
            except BlockedError as error:
                if on_block == "return":
                    return str(error)
                raise

        return guarded  # type: ignore[return-value]

    return decorate


def _checked_signature(function: Any) -> inspect.Signature:
    """The function's signature, if every parameter can be passed by name; TypeError otherwise."""
    if not callable(function):
        raise TypeError(f"guard() decorates a function, not {type(function).__name__}")
    if inspect.isgeneratorfunction(function) or inspect.isasyncgenfunction(function):
        raise TypeError("guard() cannot check what a generator yields; return the whole result instead")
    try:
        signature = inspect.signature(function)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"guard() cannot read the parameters of {function!r}: {exc}") from exc
    for parameter in signature.parameters.values():
        if parameter.kind is inspect.Parameter.VAR_POSITIONAL:
            raise TypeError(f"guard() needs every argument named, so it refuses *{parameter.name}: the policy "
                            "could not tell what those arguments are")
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            raise TypeError(f"guard() needs every argument named, so it refuses **{parameter.name}: the policy "
                            "rules name the arguments they check")
        if parameter.kind is inspect.Parameter.POSITIONAL_ONLY:
            raise TypeError(f"guard() refuses the positional-only parameter {parameter.name!r}: the checked "
                            "arguments are passed to the function by name")
    return signature


def _name_of(function: Any) -> str:
    tool = getattr(function, "__name__", None)
    if not isinstance(tool, str) or not tool or tool == "<lambda>":
        raise TypeError("guard() cannot tell this tool's name: give one, guard(firewall, name='tool_name')")
    return tool


def _bound(signature: inspect.Signature, args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """The call's arguments by parameter name, defaults included. A call that does not fit raises TypeError."""
    bound = signature.bind(*args, **kwargs)
    bound.apply_defaults()
    return dict(bound.arguments)
