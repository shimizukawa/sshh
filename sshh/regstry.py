import base64
import os
import pickle
import logging
import typing
from getpass import getpass
from pathlib import Path

from cryptography.fernet import InvalidToken, Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

REGISTRY_FILE = '~/.sshh.registry'

logger = logging.getLogger(__name__)


class Registry:
    _salt_len = 16
    InvalidToken = InvalidToken

    def __init__(self,
                 path: Path = Path(REGISTRY_FILE).expanduser()
                 ):
        self.path = path
        self._password: typing.Optional[str] = None
        self._store: typing.Optional[typing.Dict] = None

    def _get_fernet(self, salt, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def get_password(self):
        if self._password is not None:
            return self._password
        return getpass(prompt='Enter password for your registry: ')

    def set_password(self, password):
        self._password = password

    @property
    def store(self):
        if self._store is None:
            self.load()
        return self._store

    def init(self):
        if self.path.exists():
            logger.error('Registry file is already exist: %s', self.path)
            return

        self._store = {}
        self.save()
        logger.info('Registry file has been initialized: %s', self.path)

    def load(self, password=None):
        if not self.path.exists():
            logger.error("Registry file doesn't exist. Please do 'sshh init'")
            return

        if self._store is not None:
            return  # already loaded

        if password is None:
            password = self.get_password()

        data = self.path.read_bytes()
        salt, token = data[:self._salt_len], data[self._salt_len:]
        f = self._get_fernet(salt, password)
        p = f.decrypt(token)
        self._store = pickle.loads(p)
        self.set_password(password)

    def save(self, password=None):
        if self._store is None:
            return  # not loaded.

        if password is None:
            password = self.get_password()

        salt = os.urandom(self._salt_len)
        p = pickle.dumps(self._store)
        f = self._get_fernet(salt, password)
        token = f.encrypt(p)
        self.path.write_bytes(salt + token)
        self.set_password(password)

    def add_passphrase(self, group, fpath, passphrase):
        # TODO: use dataclass
        self.store.setdefault(group, {})[str(fpath)] = passphrase

    def items(self):
        return self.store.items()

    def get_group_kp(self, group):
        return self.store.get(group, {})