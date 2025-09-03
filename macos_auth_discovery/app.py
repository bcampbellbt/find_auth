#!/usr/bin/env python3
"""
Simple Flask Web Application Entry Point
Run the macOS Authorization Discovery Tool web dashboard
"""

import sys
import os
import logging

# Add the src directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.web.app import create_app

def main():
    """Main entry point for the web application"""
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create the Flask app
    app = create_app()
    
    print("=" * 60)
    print("macOS Authorization Discovery Tool - Web Dashboard")
    print("=" * 60)
    print("Starting web server...")
    print("Dashboard will be available at: http://localhost:5000")
    print("Press Ctrl+C to stop the server")
    print("=" * 60)
    
    try:
        # Run the Flask development server
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=False,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\nShutting down web server...")
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
