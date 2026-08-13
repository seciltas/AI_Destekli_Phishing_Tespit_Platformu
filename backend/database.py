import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import psycopg
from dotenv import load_dotenv
from psycopg import Connection
from psycopg.rows import dict_row


load_dotenv(Path(__file__).with_name(".env"))


class DatabaseConfigurationError(RuntimeError):
    """Raised when the PostgreSQL connection string is missing."""


def get_database_url() -> str:
    database_url = os.getenv("DATABASE_URL", "").strip()
    if not database_url:
        raise DatabaseConfigurationError(
            "DATABASE_URL backend/.env dosyasında tanımlanmalı."
        )
    return database_url


@contextmanager
def get_connection() -> Iterator[Connection]:
    with psycopg.connect(
        get_database_url(),
        row_factory=dict_row,
        connect_timeout=10,
    ) as connection:
        yield connection


def database_is_connected() -> bool:
    try:
        with get_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("select 1")
                return cursor.fetchone() is not None
    except (psycopg.Error, DatabaseConfigurationError):
        return False
