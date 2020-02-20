import logging
from logging.handlers import TimedRotatingFileHandler, RotatingFileHandler

# logging初始化工作
logging.basicConfig()

logger = logging.getLogger()

logger.setLevel(logging.DEBUG)

# 保存日志文件的文件夹的绝对路径
logs_path = ".\\logs\\"


fh = RotatingFileHandler(filename=logs_path + "log.log", maxBytes=500, encoding='utf-8')
formatter = logging.Formatter('%(asctime)s - [%(filename)s-%(funcName)s-%(lineno)d]-%(process)d-%(processName)s\
-%(thread)d-%(threadName)s]: %(message)s')
fh.setFormatter(fmt=formatter)
fh.suffix = "%y-%m-%d.log"
fh.setLevel(logging.INFO)
logger.addHandler(fh)


