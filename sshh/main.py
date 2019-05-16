#!/usr/bin/env python

import os
import sys
import subprocess
import logging
import argparse
import tempfile
from getpass import getpass
from pathlib import Path

from sshh.regstry import Registry

logger = logging.getLogger(__name__)


def test_passphrase(keyfile, phrase) -> bool:
    """confirm passphrase for the keyfile.

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


def cmd_agent(request):
    ret = subprocess.run('ssh-agent', stdout=subprocess.PIPE, encoding='ascii')
    agent_setting = ret.stdout
    logger.debug('start agent: %s', agent_setting)
    sshenv = os.environ.copy()
    # apply SSH_AGENT_PID environment variable from invoked ssh-agent
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
        # invoke new shell for invoked ssh-agent
        sshenv['PS1'] = f"[{request.group}]{sshenv['PS1']}"
        logger.info('ssh-agent PID=%s session "%s" has been started. To close this session, exit shell.',
                    sshenv['SSH_AGENT_PID'], request.group)
        shell_command = sshenv['SHELL']
        bashrc_location = Path(sshenv.get('HOME', ''), '.bashrc')
        if Path(shell_command).name.lower() == 'bash' and bashrc_location.is_file():
            # set PS1 after bash execution if shell program is bash and if bashrc is found
            with tempfile.NamedTemporaryFile('w', delete=False) as rc_file:
                # Write temp rc file that sets PS1 after loading bashrc
                rc_file.writelines([f'. {bashrc_location}\n',
                                    f'PS1="{sshenv["PS1"]}"'])
            # Set command to override rcfile with tempfile
            shell_command = [shell_command,
                             '--rcfile',
                             rc_file.name]
        subprocess.run(shell_command, env=sshenv)
    finally:
        # kill agent
        subprocess.run(['ssh-agent', '-k'], env=sshenv, stdout=subprocess.DEVNULL)
        logger.info('ssh-agent PID=%s session "%s" was closed.',
                    sshenv['SSH_AGENT_PID'], request.group)


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

    return p


def setup_logger(is_debug=False):
    if is_debug:
        logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(message)s')


def main():
    if os.environ.get('PASSPHRASE'):
        # behave as ssh-askpass when ssh-add require passphrase
        print(os.environ['PASSPHRASE'])
        sys.exit(0)

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
