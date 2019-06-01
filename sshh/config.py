import sys
import logging
import argparse
from getpass import getpass

from sshh.logging import setup_logger
from sshh.regstry import Registry

logger = logging.getLogger(__name__)


def cmd_init(request):
    request.registry.init()


def cmd_chpw(request):
    reg = request.registry
    password = getpass(prompt='Enter CURRENT password for your registry: ')
    reg.load(password)
    password1 = getpass(prompt='Enter NEW password for your registry: ')
    password2 = getpass(prompt='Enter NEW password again for verification: ')
    if password1 == password2:
        reg.save(password1)
        logging.info('Password has been changed.')
    else:
        logging.error("NEW passwords didn't match")


def get_argparser():
    p = argparse.ArgumentParser()
    p.set_defaults(func=lambda a: p.print_help())
    p.add_argument('-d', '--debug', action='store_true', default=False, help='debug mode')
    subs = p.add_subparsers(title='sub commands')

    # init
    p_init = subs.add_parser('init')
    p_init.set_defaults(func=cmd_init)

    # change password
    p_chpw = subs.add_parser('chpw')
    p_chpw.set_defaults(func=cmd_chpw)

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
