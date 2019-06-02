import logging
import argparse
from getpass import getpass

from sshh import __version__
from sshh.runner import run

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
    p.add_argument('-V', '--version', action='version', version='%(prog)s ' + __version__)
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
    run(lambda a:a.func(a), get_argparser())


if __name__ == '__main__':
    main()
