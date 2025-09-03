#!/usr/bin/env python3
"""
Flask Web Application
Provides web dashboard for the Authorization Discovery Tool
"""

import json
import os
import sys
import threading
from datetime import datetime
from typing import Dict, List

from flask import Flask, render_template, jsonify, request, send_file
import logging

# Add the src directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.command_discovery import CommandDiscoveryEngine

# Store latest results globally
latest_results = None
discovery_engine = None
discovery_thread = None



def create_app():
    """Create and configure Flask application"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'macos-auth-discovery-tool-secret'
    
    @app.route('/')
    def index():
        """Main dashboard page"""
        return render_template('dashboard.html')
    
    @app.route('/api/discovery/status')
    def get_discovery_status():
        """Get current discovery status"""
        global discovery_engine
        
        if discovery_engine:
            is_running = discovery_engine.is_discovery_running()
            progress = discovery_engine.get_progress()
            results_count = len(discovery_engine.get_results())
            
            return jsonify({
                'is_running': is_running,
                'progress_percent': progress,
                'current_check': f"Check {discovery_engine.current_check}/{discovery_engine.total_checks}",
                'total_checks': discovery_engine.total_checks,
                'completed_checks': discovery_engine.current_check,
                'results_count': results_count,
                'errors': 0
            })
        
        return jsonify({
            'is_running': False,
            'progress_percent': 0,
            'current_check': 'Not started',
            'total_checks': 15,
            'completed_checks': 0,
            'results_count': 0,
            'errors': 0
        })
    
    @app.route('/api/discovery/start', methods=['POST'])
    def start_discovery():
        """Start a new discovery process"""
        global discovery_engine, discovery_thread, latest_results
        
        try:
            # Don't start if already running
            if discovery_engine and discovery_engine.is_discovery_running():
                return jsonify({
                    'success': False,
                    'error': 'Discovery is already running'
                }), 400
            
            # Create new discovery engine
            discovery_engine = CommandDiscoveryEngine(no_sudo=False)
            
            def run_discovery():
                global latest_results
                try:
                    results = discovery_engine.discover_all_authorizations()
                    latest_results = {
                        'discovery_results': results,
                        'summary': discovery_engine.get_results_summary(),
                        'timestamp': datetime.now().isoformat(),
                        'total_found': len(results)
                    }
                except Exception as e:
                    logging.error(f"Discovery error: {e}")
            
            # Start discovery in background thread
            discovery_thread = threading.Thread(target=run_discovery)
            discovery_thread.daemon = True
            discovery_thread.start()
            
            return jsonify({
                'success': True,
                'message': 'Discovery started successfully',
                'task_id': 'discovery_' + datetime.now().strftime('%Y%m%d_%H%M%S')
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/discovery/stop', methods=['POST'])
    def stop_discovery():
        """Stop the current discovery process"""
        global discovery_engine
        
        try:
            if discovery_engine:
                discovery_engine.is_running = False
            return jsonify({
                'success': True,
                'message': 'Discovery stopped successfully'
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/discovery/results')
    def get_discovery_results():
        """Get discovery results"""
        global latest_results, discovery_engine
        
        if latest_results:
            return jsonify(latest_results)
        elif discovery_engine and discovery_engine.get_results():
            # Get results from current engine if available
            results = discovery_engine.get_results()
            return jsonify({
                'discovery_results': results,
                'summary': discovery_engine.get_results_summary(),
                'timestamp': datetime.now().isoformat(),
                'total_found': len(results)
            })
        
        # Return empty results if nothing found
        return jsonify({
            'discovery_results': [],
            'summary': {'total': 0, 'categories': {}},
            'timestamp': datetime.now().isoformat(),
            'total_found': 0
        })
    
    @app.route('/api/hardware-profile')
    def get_hardware_profile():
        """Get hardware profile information"""
        # Try to get hardware info from the latest report, or provide default
        current_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        data_dir = os.path.join(current_dir, 'data')
        
        if os.path.exists(data_dir):
            json_files = [f for f in os.listdir(data_dir) if f.endswith('.json')]
            if json_files:
                latest_file = max(json_files, key=lambda x: os.path.getctime(os.path.join(data_dir, x)))
                try:
                    with open(os.path.join(data_dir, latest_file), 'r') as f:
                        data = json.load(f)
                        if 'discovery_session' in data and 'hardware_profile' in data['discovery_session']:
                            return jsonify(data['discovery_session']['hardware_profile'])
                except Exception as e:
                    pass
        
        # Fallback hardware profile
        import platform
        import subprocess
        
        try:
            # Get macOS version details
            mac_ver = platform.mac_ver()
            
            # Get basic system info
            system_info = {
                'model': 'Unknown Mac',
                'processor': {
                    'brand': platform.processor() or 'Unknown Processor',
                    'architecture': platform.machine()
                },
                'macos_version': {
                    'ProductVersion': mac_ver[0] or 'Unknown'
                },
                'has_battery': False,
                'has_touch_id': False,
                'has_thunderbolt': False,
                'features': {
                    'has_touchid': False,
                    'has_secure_enclave': False,
                    'has_neural_engine': False,
                    'has_integrated_battery': False
                }
            }
            
            # Try to get more detailed Mac model info
            try:
                result = subprocess.run(['system_profiler', 'SPHardwareDataType'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    output = result.stdout
                    for line in output.split('\n'):
                        if 'Model Name:' in line:
                            system_info['model'] = line.split(':', 1)[1].strip()
                        elif 'Model Identifier:' in line:
                            system_info['model_identifier'] = line.split(':', 1)[1].strip()
                        elif 'Chip:' in line:
                            system_info['chip'] = line.split(':', 1)[1].strip()
                        elif 'Processor Name:' in line:
                            system_info['processor']['brand'] = line.split(':', 1)[1].strip()
            except Exception:
                pass
            
            # Check for battery presence
            try:
                result = subprocess.run(['system_profiler', 'SPPowerDataType'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and 'Battery Information:' in result.stdout:
                    system_info['has_battery'] = True
                    system_info['features']['has_integrated_battery'] = True
            except Exception:
                pass
            
            # Check for Touch ID capability
            try:
                result = subprocess.run(['system_profiler', 'SPiBridgeDataType'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and ('Touch ID' in result.stdout or 'TouchID' in result.stdout):
                    system_info['has_touch_id'] = True
                    system_info['features']['has_touchid'] = True
                    system_info['features']['has_secure_enclave'] = True
            except Exception:
                pass
            
            # Check for Thunderbolt ports
            try:
                result = subprocess.run(['system_profiler', 'SPThunderboltDataType'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and 'Thunderbolt' in result.stdout:
                    system_info['has_thunderbolt'] = True
            except Exception:
                pass
            
            return jsonify(system_info)
            
        except Exception as e:
            return jsonify({
                'model': 'Unknown Mac',
                'processor': {
                    'brand': 'Unknown Processor',
                    'architecture': platform.machine()
                },
                'macos_version': {
                    'ProductVersion': platform.mac_ver()[0] or 'Unknown'
                },
                'has_battery': False,
                'has_touch_id': False,
                'has_thunderbolt': False,
                'features': {
                    'has_touchid': False,
                    'has_secure_enclave': False,
                    'has_neural_engine': False,
                    'has_integrated_battery': False
                },
                'error': str(e)
            })
    
    @app.route('/api/progress')
    def get_progress():
        """Get current discovery progress"""
        global latest_results
        if latest_results:
            return jsonify({
                'is_running': False,
                'progress_percent': 100
            })
        return jsonify({
            'is_running': True,
            'progress_percent': 50
        })
    
    @app.route('/api/results')
    def get_results():
        """Get discovery results"""
        global latest_results
        if latest_results:
            return jsonify(latest_results)
        return jsonify({
            'error': 'No results available'
        })
    
    @app.route('/api/discovery/export/<format>')
    def export_results(format):
        """Export discovery results in various formats"""
        # Try to get the latest report from the data directory
        data_dir = 'data'
        latest_data = None
        
        if os.path.exists(data_dir):
            json_files = [f for f in os.listdir(data_dir) if f.endswith('.json')]
            if json_files:
                latest_file = max(json_files, key=lambda x: os.path.getctime(os.path.join(data_dir, x)))
                try:
                    with open(os.path.join(data_dir, latest_file), 'r') as f:
                        latest_data = json.load(f)
                except Exception as e:
                    return jsonify({'error': f'Error reading data: {str(e)}'}), 500
        
        if not latest_data:
            return jsonify({'error': 'No discovery results available'}), 404
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if format == 'json':
            filename = f'auth_discovery_export_{timestamp}.json'
            filepath = f'data/{filename}'
            
            with open(filepath, 'w') as f:
                json.dump(latest_data, f, indent=2)
            
            return send_file(filepath, as_attachment=True, download_name=filename)
        
        elif format == 'csv':
            import csv
            filename = f'auth_discovery_export_{timestamp}.csv'
            filepath = f'data/{filename}'
            
            with open(filepath, 'w', newline='') as csvfile:
                fieldnames = [
                    'element_path', 'element_name', 'element_type', 
                    'authorization_right', 'authorization_description',
                    'timestamp', 'hardware_model'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                # Extract data from the report
                auth_results = latest_data.get('authorization_results', [])
                for result in auth_results:
                    for auth_event in result.get('authorization_events', []):
                        writer.writerow({
                            'element_path': result.get('element_path', ''),
                            'element_name': result.get('element_name', ''),
                            'element_type': result.get('element_type', ''),
                            'authorization_right': auth_event.get('right_name', ''),
                            'authorization_description': auth_event.get('description', ''),
                            'timestamp': auth_event.get('timestamp', ''),
                            'hardware_model': latest_data.get('discovery_session', {}).get('hardware_profile', {}).get('model', '')
                        })
            
            return send_file(filepath, as_attachment=True, download_name=filename)
        
        else:
            return jsonify({'error': 'Unsupported export format'}), 400
    
    @app.route('/api/system-monitor/events')
    def get_system_monitor_events():
        """Get system monitor events"""
        # For now, return empty events since we don't have web_app reference
        return jsonify({
            'events': [],
            'stats': {
                'total_events': 0,
                'authorization_requests': 0,
                'errors': 0
            }
        })
    
    @app.route('/api/system-monitor/clear', methods=['POST'])
    def clear_system_monitor():
        """Clear system monitor events"""
        # For now, just return success
        return jsonify({'success': True, 'message': 'System monitor events cleared'})
    
    @app.route('/reports')
    def reports_page():
        """Reports page"""
        return render_template('reports.html')
    
    @app.route('/comparison')
    def comparison_page():
        """Version comparison page"""
        return render_template('comparison.html')
    
    @app.route('/api/reports/list')
    def list_reports():
        """List available discovery reports"""
        reports = []
        data_dir = 'data'
        
        if os.path.exists(data_dir):
            for filename in os.listdir(data_dir):
                if filename.startswith('auth_discovery_report_') and filename.endswith('.json'):
                    filepath = os.path.join(data_dir, filename)
                    stat = os.stat(filepath)
                    
                    reports.append({
                        'filename': filename,
                        'filepath': filepath,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'created': datetime.fromtimestamp(stat.st_ctime).isoformat()
                    })
        
        # Sort by creation time, newest first
        reports.sort(key=lambda x: x['created'], reverse=True)
        return jsonify(reports)
    
    @app.route('/api/reports/<filename>')
    def get_report(filename):
        """Get specific discovery report"""
        filepath = os.path.join('data', filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'Report not found'}), 404
        
        try:
            with open(filepath, 'r') as f:
                report_data = json.load(f)
            return jsonify(report_data)
        except Exception as e:
            return jsonify({'error': f'Error reading report: {str(e)}'}), 500
    
    @app.route('/api/comparison/reports', methods=['POST'])
    def compare_reports():
        """Compare two discovery reports"""
        data = request.get_json()
        report1_filename = data.get('report1')
        report2_filename = data.get('report2')
        
        if not report1_filename or not report2_filename:
            return jsonify({'error': 'Both report filenames required'}), 400
        
        try:
            # Load both reports
            with open(os.path.join('data', report1_filename), 'r') as f:
                report1 = json.load(f)
            
            with open(os.path.join('data', report2_filename), 'r') as f:
                report2 = json.load(f)
            
            # Compare authorization results
            comparison = _compare_discovery_reports(report1, report2)
            
            return jsonify(comparison)
            
        except Exception as e:
            return jsonify({'error': f'Error comparing reports: {str(e)}'}), 500
    
    return app

def _compare_discovery_reports(report1: Dict, report2: Dict) -> Dict:
    """Compare two discovery reports and return differences"""
    
    # Extract authorization rights from each report
    def extract_auth_rights(report):
        rights = set()
        for result in report.get('authorization_results', []):
            for event in result.get('authorization_events', []):
                rights.add((event['right_name'], result['element_path']))
        return rights
    
    rights1 = extract_auth_rights(report1)
    rights2 = extract_auth_rights(report2)
    
    # Find differences
    only_in_report1 = rights1 - rights2
    only_in_report2 = rights2 - rights1
    common_rights = rights1 & rights2
    
    # Create comparison summary
    comparison = {
        'report1_info': {
            'session': report1.get('discovery_session', {}),
            'total_authorizations': len(rights1)
        },
        'report2_info': {
            'session': report2.get('discovery_session', {}),
            'total_authorizations': len(rights2)
        },
        'comparison_summary': {
            'common_authorizations': len(common_rights),
            'only_in_report1': len(only_in_report1),
            'only_in_report2': len(only_in_report2),
            'total_unique': len(rights1 | rights2)
        },
        'differences': {
            'removed_authorizations': [
                {'right_name': right, 'element_path': path} 
                for right, path in only_in_report1
            ],
            'new_authorizations': [
                {'right_name': right, 'element_path': path} 
                for right, path in only_in_report2
            ]
        },
        'common_authorizations': [
            {'right_name': right, 'element_path': path} 
            for right, path in common_rights
        ]
    }
    
    return comparison


if __name__ == '__main__':
    app = create_app()
    print("Starting Flask web server...")
    print("Dashboard available at: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
