import logging
import sys
import linecache

logging.basicConfig(filename='logs/server.log', filemode="w",
                    level=logging.DEBUG, format="%(asctime)s:%(name)s:%(levelname)s:%(message)s")
def log_exc():
    try:
        exc_obj, tb = sys.exc_info()[1:]
        f = tb.tb_frame
        line_num = tb.tb_lineno
        filename = f.f_code.co_filename
        linecache.checkcache(filename)
        line = linecache.getline(filename, line_num, f.f_globals)
        logging.info('''Exception occured in ( {0},
                            line {1}, "{2}" )
                                {3}'''.format(filename, line_num, line.strip(), exc_obj))
    finally:
        del tb; del exc_obj