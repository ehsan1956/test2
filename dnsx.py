import os
import signal
import sys
import logging
from runner.options import parse_options
from runner.runner import Runner

def signal_handler(sig, frame):
    logging.info("CTRL+C pressed: Exiting")
    dnsx_runner.close()
    if options.should_save_resume():
        logging.info(f"Creating resume file: {DEFAULT_RESUME_FILE}")
        # save resume_cfg to json
        with open(DEFAULT_RESUME_FILE, 'w') as f:
            json.dump(vars(options.resume_cfg), f)
    sys.exit(1)

if __name__ == "__main__":
    options = parse_options()

    dnsx_runner = Runner(options)

    signal.signal(signal.SIGINT, signal_handler)

    err = dnsx_runner.run()
    if err:
        logging.fatal(str(err))
    dnsx_runner.close()