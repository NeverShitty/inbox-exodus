#!/usr/bin/env python3
"""
Inbox Exodus - AI-Driven File Migration Tool
Main entry point for the application
"""
import os
import sys
import logging
from rich.logging import RichHandler

from config import Config
from cli.interface import InboxExodusCLI

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if os.environ.get("DEBUG") else logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("inbox_exodus")

def main():
    """Main entry point for the Inbox Exodus tool"""
    try:
        # Initialize configuration
        config = Config()
        
        # Initialize CLI interface
        cli = InboxExodusCLI(config)
        
        # Start the CLI
        cli.start()
    except KeyboardInterrupt:
        logger.info("Inbox Exodus terminated by user")
        sys.exit(0)
    except Exception as e:
        logger.exception(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
