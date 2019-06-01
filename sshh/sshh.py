import sys
import logging
import argparse

from sshh.logging import setup_logger
from sshh.regstry import Registry

logger = logging.getLogger(__name__)


def cmd_sshh(request):
    logger.error('please use `sshh-agent`, `sshh-add`, `sshh-config` instead')


def get_argparser():
    p = argparse.ArgumentParser()
    p.set_defaults(func=lambda a: p.print_help())
    p.add_argument('-d', '--debug', action='store_true', default=False, help='debug mode')
    p.set_defaults(func=cmd_sshh)

    return p


def main():
    p = get_argparser()
    args = p.parse_args(sys.argv[1:])
    setup_logger(args.debug)
    args.registry = Registry()
    try:
        args.func(args)
    except Registry.InvalidToken:
        logger.error('Wrong password')
        sys.exit(1)


if __name__ == '__main__':
    main()
