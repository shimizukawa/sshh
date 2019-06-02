import sys
import logging

from sshh.logging import setup_logger
from sshh.regstry import Registry

logger = logging.getLogger(__name__)


def run(func, argparser):
    args = argparser.parse_args(sys.argv[1:])
    setup_logger(args.debug)
    args.registry = Registry()
    try:
        func(args)
    except Registry.InvalidToken:
        logger.error('Wrong password')
        sys.exit(1)
