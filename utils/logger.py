#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Custom logger with colored output for terminal and file logging
"""

import logging
import sys
from datetime import datetime
from typing import Optional

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Fallback if colorama not installed
    class Fore:
        CYAN = ''
        WHITE = ''
        YELLOW = ''
        RED = ''
        GREEN = ''
        MAGENTA = ''
    class Style:
        BRIGHT = ''
        RESET_ALL = ''


class ColoredFormatter(logging.Formatter):
    """Custom formatter for colored console output"""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.WHITE,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'SUCCESS': Fore.GREEN,  # Custom level
        'CRITICAL': Fore.MAGENTA + Style.BRIGHT,
    }
    
    def __init__(self, use_colors: bool = True):
        super().__init__()
        self.use_colors = use_colors and COLORAMA_AVAILABLE
    
    def format(self, record: logging.LogRecord) -> str:
        # Handle custom SUCCESS level
        if not hasattr(record, 'levelname'):
            record.levelname = 'INFO'
            
        # Get color for level
        if self.use_colors:
            color = self.COLORS.get(record.levelname, Fore.WHITE)
            reset = Style.RESET_ALL if COLORAMA_AVAILABLE else ''
        else:
            color = ''
            reset = ''
        
        # Format: [TIME] [LEVEL] Message
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        formatted = f"{color}[{timestamp}] [{record.levelname}] {record.getMessage()}{reset}"
        
        return formatted


class ColoredLogger:
    """
    Logger with colored console output and optional file logging.
    Replaces standard logging to avoid duplicate output.
    """
    
    # Custom log level for SUCCESS (between INFO and WARNING)
    SUCCESS_LEVEL = 25
    
    def __init__(self, 
                 name: str = "BitrixPentest", 
                 level: int = logging.INFO, 
                 log_file: Optional[str] = None,
                 use_colors: bool = True):
        """
        Initialize logger
        
        Args:
            name: Logger name (used for file logging only)
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Optional file path to write logs
            use_colors: Whether to use colored output
        """
        self.name = name
        self.level = level
        self.use_colors = use_colors and COLORAMA_AVAILABLE
        self.log_file = log_file
        
        # Add custom SUCCESS level if not exists
        if not hasattr(logging, 'SUCCESS'):
            logging.addLevelName(self.SUCCESS_LEVEL, 'SUCCESS')
            logging.SUCCESS = self.SUCCESS_LEVEL
        
        # File logging setup (optional)
        self.file_logger = None
        if log_file:
            self._setup_file_logging()
    
    def _setup_file_logging(self):
        """Setup file logging separately"""
        self.file_logger = logging.getLogger(f"{self.name}_file")
        self.file_logger.setLevel(logging.DEBUG)
        self.file_logger.propagate = False
        
        try:
            handler = logging.FileHandler(self.log_file, encoding='utf-8', mode='a')
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            self.file_logger.addHandler(handler)
        except Exception as e:
            print(f"Warning: Could not setup file logging: {e}")
            self.file_logger = None
    
    def _log(self, level: str, message: str, std_level: int):
        """
        Internal log method
        
        Args:
            level: Display level string
            message: Message to log
            std_level: Standard logging level for file
        """
        # Console output with colors
        if self.use_colors:
            colors = {
                'DEBUG': Fore.CYAN,
                'INFO': Fore.WHITE,
                'WARNING': Fore.YELLOW,
                'ERROR': Fore.RED,
                'SUCCESS': Fore.GREEN,
                'CRITICAL': Fore.MAGENTA + Style.BRIGHT,
            }
            color = colors.get(level, Fore.WHITE)
            reset = Style.RESET_ALL if COLORAMA_AVAILABLE else ''
        else:
            color = ''
            reset = ''
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"{color}[{timestamp}] [{level}] {message}{reset}")
        
        # File logging
        if self.file_logger:
            try:
                # Map custom levels to standard
                level_map = {
                    'SUCCESS': logging.INFO,
                }
                file_level = level_map.get(level, std_level)
                self.file_logger.log(file_level, message)
            except Exception:
                pass
    
    def debug(self, message: str):
        """Log debug message"""
        if self.level <= logging.DEBUG:
            self._log('DEBUG', message, logging.DEBUG)
    
    def info(self, message: str):
        """Log info message"""
        if self.level <= logging.INFO:
            self._log('INFO', message, logging.INFO)
    
    def warning(self, message: str):
        """Log warning message"""
        if self.level <= logging.WARNING:
            self._log('WARNING', message, logging.WARNING)
    
    def error(self, message: str):
        """Log error message"""
        if self.level <= logging.ERROR:
            self._log('ERROR', message, logging.ERROR)
    
    def success(self, message: str):
        """Log success message (custom level)"""
        if self.level <= self.SUCCESS_LEVEL:
            self._log('SUCCESS', message, logging.INFO)
    
    def critical(self, message: str):
        """Log critical message"""
        if self.level <= logging.CRITICAL:
            self._log('CRITICAL', message, logging.CRITICAL)
    
    def exception(self, message: str):
        """Log exception with traceback"""
        import traceback
        self.error(message)
        self.debug(traceback.format_exc())


# Simple test
if __name__ == "__main__":
    log = ColoredLogger(level=logging.DEBUG, log_file="test.log")
    print("Testing logger levels:")
    log.debug("Debug message")
    log.info("Info message")
    log.success("Success message")
    log.warning("Warning message")
    log.error("Error message")
    log.critical("Critical message")
    print(f"\nLog file created: test.log")