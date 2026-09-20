AWS_ACCESS_KEY_ID = "AKIAZ5QW7NRTKLM4PXV2"
DB_PASSWORD = "Sup3rS3cretPassw0rd!"
DEBUG = False


def db_url():
    return f"postgresql://app:{DB_PASSWORD}@db.internal/app"
