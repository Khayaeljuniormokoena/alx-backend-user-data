#!/usr/bin/env python3

import re
import logging
from typing import List
import os
import mysql.connector
from mysql.connector import connection

"""
Module for filtering log messages, custom logging formatter,
creating a logger, connecting to a secure database, and
retrieving and logging user data.
"""

def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    for field in fields:
        message = re.sub(f"{field}=[^{separator}]*", f"{field}={redaction}", message)
    return message

class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Formats the log record, redacting sensitive information"""
        record.msg = filter_datum(self.fields, self.REDACTION, record.msg, self.SEPARATOR)
        return super(RedactingFormatter, self).format(record)

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def get_logger() -> logging.Logger:
    """
    Creates and configures a logger

    Returns:
        logging.Logger: Configured logger instance
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(fields=PII_FIELDS)
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)

    return logger

def get_db() -> connection.MySQLConnection:
    """
    Connects to the MySQL database

    Returns:
        mysql.connector.connection.MySQLConnection: MySQL database connection
    """
    return mysql.connector.connect(
        user=os.getenv('PERSONAL_DATA_DB_USERNAME', 'root'),
        password=os.getenv('PERSONAL_DATA_DB_PASSWORD', ''),
        host=os.getenv('PERSONAL_DATA_DB_HOST', 'localhost'),
        database=os.getenv('PERSONAL_DATA_DB_NAME')
    )


def main():
    """Main function to retrieve and log user data"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")

    fields = ("name", "email", "phone", "ssn", "password")
    logger = get_logger()

    for row in cursor:
        message = f"name={row[0]}; email={row[1]}; phone={row[2]}; ssn={row[3]}; password={row[4]}; ip={row[5]}; last_login={row[6]}; user_agent={row[7]};"
        logger.info(message)

    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
