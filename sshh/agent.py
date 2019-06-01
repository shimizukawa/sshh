#!/usr/bin/env python

import os
import sys
import subprocess
import logging
import argparse
import tempfile
from pathlib import Path

from sshh.logging import setup_logger
from sshh.regstry import Registry

logger = logging.getLogger(__name__)


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

    rc_file = None
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
        if 'PS1' in sshenv:
            sshenv['PS1'] = f"[{request.group}]{sshenv['PS1']}"
        else:
            sshenv['PS1'] = f"[{request.group}]"
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
        else:
            # For safely removing temp file
            rc_file = None
        subprocess.run(shell_command, env=sshenv)
    finally:
        # kill agent
        subprocess.run(['ssh-agent', '-k'], env=sshenv, stdout=subprocess.DEVNULL)
        # remove temp rc file
        if rc_file:
            os.unlink(rc_file.name)
        logger.info('ssh-agent PID=%s session "%s" was closed.',
                    sshenv['SSH_AGENT_PID'], request.group)


def get_argparser():
    p = argparse.ArgumentParser()
    p.set_defaults(func=lambda a: p.print_help())
    p.add_argument('-d', '--debug', action='store_true', default=False, help='debug mode')
    p.add_argument('-g', '--group', type=str, default='default', help='group name')
    p.set_defaults(func=cmd_agent)

    return p


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
