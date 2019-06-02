import sys
import logging
import argparse
from getpass import getpass
from pathlib import Path

from sshh import __version__
from sshh.regstry import Registry
from sshh.runner import run
from sshh.proc import call_with_phrase

logger = logging.getLogger(__name__)


def test_passphrase(keyfile, phrase) -> bool:
    """confirm passphrase for the keyfile.

    :param keyfile: ssh key file path
    :param phrase: passphrase for keyfile
    :return: True if the keyfile/phrase pair is matched, otherwise False.
    """
    return call_with_phrase(['ssh-keygen', '-yf', str(keyfile)], phrase)


def cmd_add(request):
    passphrase = getpass(prompt='Enter passphrase for the keyfile: ')
    fpath = Path(request.keyfile.name).absolute()
    if test_passphrase(fpath, passphrase):
        request.registry.add_passphrase(request.group, fpath, passphrase)
        request.registry.save()
        logger.info('The keyfile is registered.')
    else:
        logger.error('passphrase for the keyfile is not correct.')


def cmd_list(request):
    for g, d in request.registry.items():
        print(f'[{g}]')
        for fn in d:
            print(fn)
        print()


def get_argparser():
    p = argparse.ArgumentParser()
    p.add_argument('-V', '--version', action='version', version='%(prog)s ' + __version__)
    p.add_argument('-d', '--debug', action='store_true', default=False, help='debug mode')
    p.add_argument('-g', '--group', type=str, default='default', help='group name')
    eg = p.add_mutually_exclusive_group(required=True)
    eg.add_argument('-l', '--list', action='store_true', default=False, help='list keys')
    eg.add_argument('keyfile', nargs='?', type=argparse.FileType('r'), default=None, help='ssh secret key file')

    return p


def main():
    p = get_argparser()
    args = p.parse_args(sys.argv[1:])

    if args.list:
        cmd = cmd_list
    else:
        cmd = cmd_add
    try:
        run(cmd, p)
    except Registry.InvalidToken:
        logger.error('Wrong password')
        sys.exit(1)


if __name__ == '__main__':
    main()
