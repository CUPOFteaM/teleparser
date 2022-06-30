import argparse
import os
import sys
from teleparser import VERSION, process

import logger


if __name__ == "__main__":

    if sys.version_info[0] < 3:
        sys.exit("Python 3 or a more recent version is required.")

    description = "Telegram parser version {}".format(VERSION)
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("infilename", help="input file cache4.db")
    parser.add_argument("outdirectory", help="output directory, must exist")
    parser.add_argument("-v", "--verbose", action="count", help="verbose level, -v to -vvv")
    args = parser.parse_args()

    logger.configure_logging(args.verbose)

    if os.path.exists(args.infilename):
        if os.path.isdir(args.outdirectory):
            process(args.infilename, args.outdirectory)
        else:
            logger.error("Output directory [%s] does not exist!", args.outdirectory)
    else:
        logger.error("The provided input file does not exist!")
