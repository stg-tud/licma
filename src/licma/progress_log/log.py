import logging
import datetime
import os

logger = logging.getLogger('root')


def create_logger_file(log_path, log_level):
    log_format = "%(asctime)s | %(levelname)s | %(message)s"

    if not os.path.exists(log_path):
        os.makedirs(log_path)

    # logger file output
    logging.basicConfig(filename=os.path.join(log_path, 'licma' + str(datetime.datetime.now()) + '.log'),
                        level=log_level,
                        format=log_format,
                        datefmt='%m-%d %H:%M',
                        filemode='w')


def create_logger_cli(log_level):
    log_format = "%(asctime)s | %(levelname)s | %(message)s"

    # logger console output
    console = logging.StreamHandler()
    console.setLevel(log_level)
    formatter = logging.Formatter(log_format)
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)
