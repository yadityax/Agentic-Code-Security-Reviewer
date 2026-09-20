import config


def test_url():
    assert config.db_url().startswith("postgresql://app:")
