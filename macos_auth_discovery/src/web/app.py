#!/usr/bin/env python3
"""
Flask Web Application
Provides web dashboard for the Authorization Discovery Tool
"""

import json
import os
import threading
from datetime import datetime
from typing import Dict, List

from flask import Flask, render_template, jsonify, request, send_file
import logging

# Store latest results globally
latest_results = None



def create_app():
    """Create and configure Flask application"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'macos-auth-discovery-tool-secret'
    
    @app.route('/')
    def index():
        """Main dashboard page"""
        return render_template('dashboard.html')
    
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
        if not web_app.discovery_engine:
            return jsonify({'error': 'No discovery results available'}), 404
        
        results = web_app.discovery_engine.get_results()
        events = [event.to_dict() for event in web_app.discovery_engine.get_authorization_events()]
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if format == 'json':
            data = {
                'discovery_results': results,
                'authorization_events': events,
                'hardware_profile': web_app.hardware_manager.get_hardware_profile(),
                'export_timestamp': datetime.now().isoformat()
            }
            
            filename = f'auth_discovery_{timestamp}.json'
            filepath = f'data/{filename}'
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            
            return send_file(filepath, as_attachment=True, download_name=filename)
        
        elif format == 'csv':
            import csv
            filename = f'auth_discovery_{timestamp}.csv'
            filepath = f'data/{filename}'
            
            with open(filepath, 'w', newline='') as csvfile:
                fieldnames = [
                    'element_path', 'element_name', 'element_type', 
                    'authorization_right', 'authorization_description',
                    'timestamp', 'hardware_model'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in results:
                    for auth_event in result.get('authorization_events', []):
                        writer.writerow({
                            'element_path': result['element_path'],
                            'element_name': result['element_name'],
                            'element_type': result['element_type'],
                            'authorization_right': auth_event['right_name'],
                            'authorization_description': auth_event['right_description'],
                            'timestamp': result['timestamp'],
                            'hardware_model': result['hardware_profile']['model']
                        })
            
            return send_file(filepath, as_attachment=True, download_name=filename)
        
        else:
            return jsonify({'error': 'Unsupported format'}), 400
    
    @app.route('/api/system-monitor/events')
    def get_system_monitor_events():
        """Get system monitor events"""
        events = [event.to_dict() for event in web_app.system_monitor.get_authorization_events()]
        stats = web_app.system_monitor.get_summary_stats()
        
        return jsonify({
            'events': events,
            'stats': stats
        })
    
    @app.route('/api/system-monitor/clear', methods=['POST'])
    def clear_system_monitor():
        """Clear system monitor events"""
        web_app.system_monitor.clear_events()
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
