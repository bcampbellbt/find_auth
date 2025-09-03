#!/usr/bin/env python3
"""
macOS System Settings Authorization Discovery Tool
Main entry point for the application
"""

import sys
import os
import argparse
import logging
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from core.discovery_engine import AuthorizationDiscoveryEngine
from core.system_monitor import SystemLevelMonitor
from core.hardware_profile import HardwareProfileManager
from web.app import create_app

def setup_logging(level=logging.INFO):
    """Setup logging configuration"""
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('auth_discovery.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def main():
    parser = argparse.ArgumentParser(description='macOS System Settings Authorization Discovery Tool')
    parser.add_argument('--mode', choices=['discover', 'web', 'both'], default='both',
                       help='Mode to run: discover only, web dashboard only, or both')
    parser.add_argument('--port', type=int, default=5000,
                       help='Port for Flask web application')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug mode')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help='Logging level')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = getattr(logging, args.log_level)
    setup_logging(log_level)
    
    logger = logging.getLogger(__name__)
    logger.info("Starting macOS System Settings Authorization Discovery Tool")
    
    try:
        if args.mode in ['discover', 'both']:
            logger.info("Starting authorization discovery process...")
            
            # Initialize hardware profile manager
            hardware_manager = HardwareProfileManager()
            
            # Initialize system monitor
            system_monitor = SystemLevelMonitor()
            
            # Initialize discovery engine
            discovery_engine = AuthorizationDiscoveryEngine(
                hardware_manager=hardware_manager,
                system_monitor=system_monitor
            )
            
            # Start discovery process
            discovery_engine.start_discovery()
        
        if args.mode in ['web', 'both']:
            logger.info(f"Starting Flask web application on port {args.port}...")
            
            # Create and run Flask app
            app = create_app()
            app.run(host='0.0.0.0', port=args.port, debug=args.debug)
            
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
    except Exception as e:
        logger.error(f"Application error: {e}")
        if args.debug:
            raise
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
