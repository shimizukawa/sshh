import logging
import argparse

from sshh import __version__
from sshh.runner import run

logger = logging.getLogger(__name__)


def cmd_sshh(request):
    logger.error('please use `sshh-agent`, `sshh-add`, `sshh-config` instead')


def get_argparser():
    p = argparse.ArgumentParser()
    p.add_argument('-V', '--version', action='version', version='%(prog)s ' + __version__)
    p.add_argument('-d', '--debug', action='store_true', default=False, help='debug mode')

    return p


def main():
    run(cmd_sshh, get_argparser())


if __name__ == '__main__':
    main()
