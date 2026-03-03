"""CLI entry point with argparse subcommands."""

from __future__ import annotations

import argparse
import sys

from ssl_manager.config import load_config


def _cmd_list(args: argparse.Namespace) -> None:
    """List all configured domains and servers."""
    cfg = load_config(args.config)
    print("=" * 60)
    print("  Configured Domains & Servers")
    print("=" * 60)
    for dc in cfg.domains:
        print(f"\n  Domain: {dc.domain}")
        if not dc.servers:
            print("    (no servers configured)")
            continue
        for i, s in enumerate(dc.servers, 1):
            print(f"    Server #{i}: {s.user}@{s.host}:{s.port}")
            print(f"      cert: {s.cert_path}")
            print(f"      key:  {s.key_path}")
            print(f"      reload: {s.reload_cmd}")
    print(f"\n  Cert storage: {cfg.cert_storage_dir}")
    print(f"  Renew before: {cfg.options.renew_before_days} days")
    print("=" * 60)


def _cmd_check(args: argparse.Namespace) -> None:
    """Check ACME status and certificate expiry."""
    cfg = load_config(args.config)
    from ssl_manager.core.cert_manager import CertManager

    manager = CertManager(cfg)
    manager.check(domain=args.domain)


def _cmd_apply(args: argparse.Namespace) -> None:
    """Apply for a new certificate."""
    cfg = load_config(args.config)
    from ssl_manager.core.cert_manager import CertManager

    manager = CertManager(cfg)
    manager.apply(domain=args.domain, dry_run=args.dry_run)


def _cmd_deploy(args: argparse.Namespace) -> None:
    """Deploy certificate to servers."""
    cfg = load_config(args.config)
    from ssl_manager.core.cert_manager import CertManager

    manager = CertManager(cfg)
    manager.deploy(domain=args.domain, server=args.server, dry_run=args.dry_run)


def _cmd_renew(args: argparse.Namespace) -> None:
    """Batch renew: check -> apply -> deploy."""
    cfg = load_config(args.config)
    from ssl_manager.core.cert_manager import CertManager

    manager = CertManager(cfg)
    manager.renew(domain=args.domain, dry_run=args.dry_run)


def _cmd_diagnose(args: argparse.Namespace) -> None:
    """Diagnose ACME connectivity and Aliyun API status."""
    cfg = load_config(args.config)
    from ssl_manager.core.cert_manager import CertManager

    manager = CertManager(cfg)
    manager.diagnose()


def _cmd_setup_persist(args: argparse.Namespace) -> None:
    """Set up persistent DNS record for dns-persist-01."""
    cfg = load_config(args.config)
    from ssl_manager.core.cert_manager import CertManager

    manager = CertManager(cfg)
    manager.setup_persist(
        domain=args.domain,
        policy=args.policy,
        persist_until=args.persist_until,
        dry_run=args.dry_run,
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="ssl-manager",
        description="Alibaba Cloud SSL certificate automation tool",
    )
    parser.add_argument(
        "--config", "-c", default=None, help="Path to config.yaml"
    )

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # list
    sub.add_parser("list", help="List configured domains and servers")

    # check
    p_check = sub.add_parser("check", help="Check ACME status and cert expiry")
    p_check.add_argument("--domain", "-d", default=None, help="Filter by domain")

    # apply
    p_apply = sub.add_parser("apply", help="Apply for a new certificate")
    p_apply.add_argument("--domain", "-d", required=True, help="Target domain")
    p_apply.add_argument(
        "--dry-run", action="store_true", help="Show plan without executing"
    )

    # deploy
    p_deploy = sub.add_parser("deploy", help="Deploy certificate to servers")
    p_deploy.add_argument("--domain", "-d", required=True, help="Target domain")
    p_deploy.add_argument("--server", "-s", default=None, help="Filter by server host")
    p_deploy.add_argument(
        "--dry-run", action="store_true", help="Show plan without executing"
    )

    # renew
    p_renew = sub.add_parser("renew", help="Batch renew certificates")
    p_renew.add_argument("--domain", "-d", default=None, help="Filter by domain")
    p_renew.add_argument(
        "--dry-run", action="store_true", help="Show plan without executing"
    )

    # diagnose
    sub.add_parser(
        "diagnose",
        help="Diagnose ACME connectivity and Aliyun API status",
    )

    # setup-persist
    p_persist = sub.add_parser(
        "setup-persist",
        help="Set up persistent DNS record for dns-persist-01",
    )
    p_persist.add_argument("--domain", "-d", required=True, help="Target domain")
    p_persist.add_argument(
        "--policy", default=None, help="Policy string (e.g. 'wildcard')"
    )
    p_persist.add_argument(
        "--persist-until", type=int, default=None,
        help="UNIX timestamp for record expiry",
    )
    p_persist.add_argument(
        "--dry-run", action="store_true", help="Show plan without executing"
    )

    return parser


def main() -> None:
    """CLI main entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    cmd_map = {
        "list": _cmd_list,
        "check": _cmd_check,
        "apply": _cmd_apply,
        "deploy": _cmd_deploy,
        "renew": _cmd_renew,
        "diagnose": _cmd_diagnose,
        "setup-persist": _cmd_setup_persist,
    }

    try:
        cmd_map[args.command](args)
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
    except EnvironmentError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"[ERROR] Unexpected: {e}", file=sys.stderr)
        sys.exit(1)
