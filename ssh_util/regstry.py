import base64
import os
import pickle
from pathlib import Path

from cryptography.fernet import InvalidToken, Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ssh_util.config import REGISTRY_FILE


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