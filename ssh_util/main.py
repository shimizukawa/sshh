#!/usr/bin/env python

import os
import sys
import pickle
import subprocess
import logging
import argparse
import base64
from getpass import getpass
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ssh_util.config import REGISTRY_FILE


logger = logging.getLogger(__name__)


def test_passphrase(keyfile, phrase) -> bool:
    """return True if the keyfile/phrase pair is matched.

    :param keyfile: ssh key file path
    :param phrase: passphrase for keyfile
    :return: True if the keyfile/phrase pair is matched, otherwise False.
    """
    env = os.environ.copy()
    env['SSH_ASKPASS'] = os.path.abspath(sys.argv[0])
    env['DISPLAY'] = ':999'
    env['PASSPHRASE'] = phrase
    p = subprocess.Popen(
        ['ssh-keygen', '-yf', str(keyfile)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        encoding='ascii',
        preexec_fn=os.setsid
    )
    try:
        r = p.communicate(timeout=1)
        logger.debug('ssh-add return %s: %s', p.returncode, r)
    except subprocess.TimeoutExpired:
        logger.error('timeout')
        p.kill()
        logger.error(p.communicate())

    return p.returncode == 0


class Registry:
    _salt_len = 16
    InvalidToken = InvalidToken

    def __init__(self,
                 password:str,
                 path: Path = Path(REGISTRY_FILE).expanduser()
                 ):
        self.path = path
        self.password = password
        self._store: dict = {}
        self.load()

    def _get_fernet(self, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password.encode()))
        return Fernet(key)

    def load(self):
        if self.path.exists():
            data = self.path.read_bytes()
            salt, token = data[:self._salt_len], data[self._salt_len:]
            f = self._get_fernet(salt)
            p = f.decrypt(token)
            self._store = pickle.loads(p)
        else:
            self.save()  # write test

    def save(self):
        salt = os.urandom(self._salt_len)
        p = pickle.dumps(self._store)
        f = self._get_fernet(salt)
        token = f.encrypt(p)
        self.path.write_bytes(salt + token)

    def add_passphrase(self, group, fpath, passphrase):
        # TODO: use dataclass
        self._store.setdefault(group, {})[str(fpath)] = passphrase

    def items(self):
        return self._store.items()

    def get_group_kp(self, group):
        return self._store.get(group, {})


def cmd_add(request):
    passphrase = getpass(prompt='Enter passphrase for the keyfile: ')
    fpath = Path(request.keyfile.name).absolute()
    if test_passphrase(fpath, passphrase):   # 鍵のパスフレーズを検査
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


def cmd_agent(request):
    ret = subprocess.run('ssh-agent', stdout=subprocess.PIPE, encoding='ascii')
    agent_setting = ret.stdout
    logger.debug('start agent: %s', agent_setting)
    sshenv = os.environ.copy()
    # 起動したssh-agentのSSH_AGENT_PIDを環境変数に登録する
    sshenv.update({
        k: v.rstrip(';')
        for k, v in [part.split('=') for part in agent_setting.split() if '=' in part]
    })
    tempenv = sshenv.copy()
    tempenv['SSH_ASKPASS'] = os.path.abspath(sys.argv[0])
    tempenv['DISPLAY'] = ':999'
    logger.debug('env: %s', tempenv)

    logger.info('Registering keys for session "%s"', request.group)
    group_kp = request.registry.get_group_kp(request.group)

    if not group_kp:
        logger.info('Empty group "%s", abort.', request.group)
        return

    try:
        for keyfile, phrase in group_kp.items():
            tempenv['PASSPHRASE'] = phrase
            p = subprocess.Popen(
                ['ssh-add', str(keyfile)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=tempenv,
                encoding='ascii',
                preexec_fn=os.setsid
            )
            try:
                r = p.communicate(timeout=1)
                logger.debug('ssh-add return %s: %s', p.returncode, r)
            except subprocess.TimeoutExpired:
                p.kill()
                raise RuntimeError('Something wrong ... \n%s', p.communicate())
    except RuntimeError as e:
        logger.error(e)
    else:
        # shellを起動する
        sshenv['PS1'] = f"[{request.group}]{sshenv['PS1']}"
        logger.info('ssh-agent PID=%s session "%s" has been started. To close this session, exit shell.',
                    sshenv['SSH_AGENT_PID'], request.group)
        subprocess.run (sshenv['SHELL'], env=sshenv)
    finally:
        # agentを終了
        subprocess.run(['ssh-agent', '-k'], env=sshenv, stdout=subprocess.DEVNULL)
        logger.info('ssh-agent PID=%s session "%s" was closed.',
                    sshenv['SSH_AGENT_PID'], request.group)


def get_argparser():
    p = argparse.ArgumentParser()
    p.set_defaults(func=lambda a: p.print_help())
    p.add_argument('-d', '--debug', action='store_true', default=False, help='debug mode')
    subs = p.add_subparsers(title='sub commands')

    # add key
    p_add = subs.add_parser('add')
    p_add.add_argument('-g', '--group', type=str, default='default', help='group name')
    p_add.add_argument('keyfile', type=argparse.FileType('r'), help='ssh secret key file')
    p_add.set_defaults(func=cmd_add)

    # list keys
    p_list = subs.add_parser('list')
    p_list.set_defaults(func=cmd_list)

    # invoke agent
    p_agent = subs.add_parser('agent')
    p_agent.add_argument('-g', '--group', type=str, default='default', help='group name')
    p_agent.set_defaults(func=cmd_agent)

    # change password
    # TODO provide change password feature

    return p


def setup_logger(is_debug=False):
    if is_debug:
        logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(message)s')


def main():
    if os.environ.get('PASSPHRASE'):
        # ssh-addから呼ばれる、ssh-askpassとしての動作
        print(os.environ['PASSPHRASE'])
        sys.exit(0)

    p = get_argparser()
    args = p.parse_args(sys.argv[1:])
    setup_logger(args.debug)
    password = getpass(prompt='Enter password for your registry: ')
    try:
        args.registry = Registry(password=password)
    except Registry.InvalidToken:
        logger.error('Wrong password')
        sys.exit(1)
    args.func(args)


if __name__ == '__main__':
    main()
