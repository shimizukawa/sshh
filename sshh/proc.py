import os
import subprocess
import logging

from sshh.sshh_askpass import get_executable_askpass

logger = logging.getLogger(__name__)


def call_with_phrase(cmd_args, phrase, env=None) -> bool:
    if env is None:
        env = os.environ.copy()
    env = env.copy()
    env['SSH_ASKPASS'] = get_executable_askpass()
    env['DISPLAY'] = ':999'
    env['PASSPHRASE'] = phrase
    p = subprocess.Popen(
        cmd_args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        encoding='ascii',
        preexec_fn=os.setsid
    )
    try:
        r = p.communicate(timeout=1)
        logger.debug('"%s" return %s: %s', ' '.join(cmd_args), p.returncode, r)
    except subprocess.TimeoutExpired:
        logger.error('timeout')
        p.kill()
        logger.error(p.communicate())

    return p.returncode == 0
