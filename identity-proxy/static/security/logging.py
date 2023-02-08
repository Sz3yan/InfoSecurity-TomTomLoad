import os
import logging

from ..classes.config import CONSTANTS
# from ..classes.storage import GoogleCloudStorage

# storage = GoogleCloudStorage()


log_destination = os.path.join(CONSTANTS.IP_CONFIG_FOLDER, "identity-proxy.log")


class IDLogger:
    def __init__(self, name):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        handler = logging.FileHandler(log_destination)


        handler.setLevel(logging.DEBUG)

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)

        self.logger.addHandler(handler)

    def debug(self, message):
        self.logger.debug(message)

    def info(self, message):
        self.logger.info(message)

    def warning(self, message):
        self.logger.warning(message)

    def error(self, message):
        self.logger.error(message)

    def critical(self, message):
        self.logger.critical(message)
