import logging
from ospf_attack.utils.logging import setup_logging


def test_setup_logging_returns_logger():
    logger = setup_logging(verbose=False)
    assert isinstance(logger, logging.Logger)


def test_setup_logging_verbose():
    logger = setup_logging(verbose=True)
    assert logger.level == logging.DEBUG


def test_setup_logging_quiet():
    logger = setup_logging(verbose=False)
    assert logger.level == logging.INFO
