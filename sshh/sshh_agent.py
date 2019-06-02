import os
import subprocess
import logging
import argparse
import tempfile
from pathlib import Path

from sshh import __version__
from sshh.runner import run
from sshh.proc import call_with_phrase

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
    logger.debug('env: %s', sshenv)

    logger.info('Registering keys for session "%s"', request.group)
    group_kp = request.registry.get_group_kp(request.group)

    if not group_kp:
        logger.info('Empty group "%s", abort.', request.group)
        return

    rc_file = None
    try:
        for keyfile, phrase in group_kp.items():
            if not call_with_phrase(['ssh-add', str(keyfile)], phrase, env=sshenv):
                raise RuntimeError('Something wrong ... ')
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
    p.add_argument('-V', '--version', action='version', version='%(prog)s ' + __version__)
    p.add_argument('-d', '--debug', action='store_true', default=False, help='debug mode')
    p.add_argument('-g', '--group', type=str, default='default', help='group name')

    return p


def main():
    run(cmd_agent, get_argparser())


if __name__ == '__main__':
    main()
