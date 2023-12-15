"""This module acts as a central logging capability"""
import logging
import os
from datetime import datetime

LOGFILE = "PDFtoCSV"

class Logger:
    """
    Provides logging capabilities
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
            logger = logging.getLogger('Logger') # pylint: disable=redefined-outer-name

            # File Handler with milliseconds
            file_formatter = logging.Formatter('[%(asctime)s.%(msecs)03d] %(levelname)s: %(message)s', # pylint: disable=line-too-long
                                                datefmt='%Y-%m-%d %H:%M:%S')
            current_time = datetime.now().strftime('%Y-%m-%d')
            if not os.path.exists('logs'):
                os.makedirs('logs')
            file_handler = logging.FileHandler(f'logs/{current_time}_{LOGFILE}.log')
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)

            # Stream Handler without milliseconds
            stream_formatter = logging.Formatter('[\033[36m%(asctime)s\033[0m] %(message)s', datefmt='%H:%M:%S')
            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(stream_formatter)
            stream_handler.addFilter(cls.ColorFilter())
            logger.addHandler(stream_handler)

            logger.setLevel(logging.DEBUG)

            cls._instance.logger = logger

        return cls._instance

    class ColorFilter(logging.Filter):
        """This class is for colors :)"""
        def filter(self, record):
            if record.levelname == 'DEBUG':
                record.msg = "[\033[30mDEBUG\033[0m]: " + record.msg
            elif record.levelname == 'INFO':
                record.msg = "[\033[92mINFO\033[0m]: " + record.msg
            elif record.levelname == 'WARNING':
                record.msg = "[\033[33mWARNING\033[0m]: " + record.msg
            elif record.levelname == 'ERROR':
                record.msg = "[\033[31mERROR\033[0m]: " + record.msg
            elif record.levelname == 'CRITICAL':
                record.msg = "[\033[91mCRITICAL\033[0m]: " + record.msg
            else:
                return False

            return True

    def log_info(self, message): # pylint: disable=missing-function-docstring
        self.logger.info(message) # pylint: disable=no-member

    def log_debug(self, message): # pylint: disable=missing-function-docstring
        self.logger.debug(message) # pylint: disable=no-member

    def log_warning(self, message): # pylint: disable=missing-function-docstring
        self.logger.warning(message) # pylint: disable=no-member

    def log_error(self, message): # pylint: disable=missing-function-docstring
        self.logger.error(message) # pylint: disable=no-member

    def log_critical(self, message): # pylint: disable=missing-function-docstring
        self.logger.critical(message) # pylint: disable=no-member


# Creation of logger instance and methods
logger = Logger()
log_debug = logger.log_debug
log_info = logger.log_info
log_warning = logger.log_warning
log_error = logger.log_error
log_critical = logger.log_critical
