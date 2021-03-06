#!/usr/bin/env python

from server import app
from db import db


def main():
    with app.app_context():
        db.create_all()


if __name__ == '__main__':
    main()
