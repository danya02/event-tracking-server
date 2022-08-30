import peewee as pw
import secrets
import hashlib
import hmac
db = pw.SqliteDatabase('./events.db')

def create_table(cls):
    db.create_tables([cls])
    return cls

class MyModel(pw.Model):
    class Meta:
        database = db

@create_table
class SecretKey(MyModel):
    key = pw.BlobField()
    created_at = pw.DateTimeField(default=pw.datetime.datetime.now)

    @classmethod
    def get_secret(cls):
        existing_row = cls.select().get_or_none()
        if existing_row:
            if existing_row.created_at < pw.datetime.datetime.now() - pw.datetime.timedelta(days=1):
                existing_row.delete_instance()
                return cls.get_secret()
            else:
                return existing_row.key
        else:
            new_key = cls.create(key=secrets.token_bytes(32))
            return new_key.key


@create_table
class User(MyModel):
    username = pw.CharField(unique=True)
    scrypt_hash = pw.BlobField()
    scrypt_salt = pw.BlobField()
    scrypt_N = pw.IntegerField(default=16384)
    scrypt_r = pw.IntegerField(default=8)
    scrypt_p = pw.IntegerField(default=1)

    def check_password(self, password):
        password_hash = hashlib.scrypt(password.encode(), salt=self.scrypt_salt, n=self.scrypt_N, r=self.scrypt_r, p=self.scrypt_p)
        return hmac.compare_digest(password_hash, self.scrypt_hash)

@create_table
class EventStream(MyModel):
    owner = pw.ForeignKeyField(User, backref='streams')
    name = pw.CharField()
    is_stateful = pw.BooleanField(default=False)  # If true, the stream records a series of state transitions.
                                                  # If false, the stream records a series of points in time, and the state field is ignored.
    expected_states = pw.CharField(null=True)     # A space-separated list of expected states. We will record others but we will show these in the UI.
    password = pw.CharField()

@create_table
class Event(MyModel):
    stream = pw.ForeignKeyField(EventStream, backref='events', on_delete='CASCADE')
    unix_millis = pw.BigIntegerField()
    new_state = pw.CharField(null=True)

    by_ip = pw.IPField(null=True)

    class Meta:
        indexes = (
            (('stream', 'unix_millis'), False),
        )