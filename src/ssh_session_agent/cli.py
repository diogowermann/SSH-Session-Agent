from __future__ import annotations

import argparse
import json
import logging
import sys

from .agent import Agent, run_daemon
from .config import DEFAULT_CONFIG_PATH, ConfigurationError, Settings
from .journal import JournalReader
from .preflight import detect_ssh_unit, run_preflight


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ssh-session-agent")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="path to agent JSON configuration")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("preflight", help="validate local prerequisites without sending telemetry")
    sub.add_parser("once", help="run one collection/delivery cycle")
    sub.add_parser("daemon", help="run continuously")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        settings = Settings.from_file(args.config)
    except ConfigurationError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    if args.command == "preflight":
        results = run_preflight(settings)
        for item in results:
            print(f"{'OK' if item.ok else 'FAIL'}\t{item.name}\t{item.detail}")
        return 0 if all(item.ok for item in results) else 1

    try:
        unit = detect_ssh_unit(settings.journal_unit)
    except RuntimeError as exc:
        print(f"preflight error: {exc}", file=sys.stderr)
        return 1

    agent = Agent(settings, journal_reader=JournalReader(unit))
    if args.command == "once":
        print(json.dumps(agent.run_cycle(), sort_keys=True))
        return 0
    return run_daemon(agent, poll_seconds=settings.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
