import sys
import logging


class StreamToLogger(object):
    """
    Redirects log writes to a logger instance.
    """
    def __init__(self, logger, level):
       self.logger = logger
       self.level = level
       self.linebuf = ''

    def write(self, buf):
       for line in buf.rstrip().splitlines():
          self.logger.log(self.level, line.rstrip())

    def flush(self):
        pass


logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s:%(levelname)s:%(name)s:%(message)s',
        filename='out.log',
        filemode='a'
        )

log = logging.getLogger('app_log')
sys.stdout = StreamToLogger(log,logging.INFO)
sys.stderr = StreamToLogger(log,logging.ERROR)
