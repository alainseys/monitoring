from flask import Flask, render_template, request, redirect, url_for, session, flash

from datetime import datetime, date, timedelta
import os
import threading
import time
import logging
from logging.handlers import RotatingFileHandler
import requests
from ping3 import ping
from dotenv import load_dotenv

# Import db from extensions
from extensions import db

# Import functions from new modules
from functions.ldap import authenticate_user
from functions.maintenance_scheduler import maintenance_scheduler

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nXj2Ui1EP0scfmv8'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///status.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

# Initialize SQLAlchemy with the app
db.init_app(app)


# Import models after db initialization to register them
from models import Status, Server, StatusHistory, ScheduledMaintenance, HttpCheck, PingCheck

# Configure logging
LOG_DIR = 'logs'
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
log_handler = RotatingFileHandler(os.path.join(LOG_DIR, 'admin_actions.log'), maxBytes=1000000, backupCount=5)
log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - User: %(user)s - Action: %(action)s'))
log_handler.setLevel(logging.INFO)
app.logger.addHandler(log_handler)
app.logger.setLevel(logging.INFO)

# Login required decorator
def login_required(f):
    def wrap(*args, **kwargs):
        if 'username' not in session:
            flash('Please login first.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# app.py (only showing the modified server_checker function)
def server_checker(app):
    while True:
        with app.app_context():  # Use the passed app for context
            now = datetime.utcnow()
            servers = Server.query.all()
            for server in servers:
                enabled_http_checks = [c for c in server.http_checks if c.enabled]
                enabled_pings = [c for c in server.ping_checks if c.enabled]
                total_checks = len(enabled_http_checks) + len(enabled_pings)
                if total_checks == 0:
                    continue
                active_maint = ScheduledMaintenance.query.filter_by(server_id=server.id, is_active=True).first()
                if active_maint:
                    continue
                failed = 0
                failed_http_labels = []
                failed_ping_labels = []
                for check in enabled_http_checks:
                    try:
                        resp = requests.get(check.url, timeout=10)
                        check.last_checked = now
                        check.last_result = f"Success (Status: {resp.status_code})" if resp.status_code == 200 else f"Failed (Status: {resp.status_code})"
                        if resp.status_code != 200:
                            failed += 1
                            failed_http_labels.append(check.label)
                    except requests.exceptions.RequestException as e:
                        check.last_checked = now
                        check.last_result = f"Failed ({str(e)})"
                        failed += 1
                        failed_http_labels.append(check.label)
                for check in enabled_pings:
                    try:
                        result = ping(check.hostname, timeout=2)
                        check.last_checked = now
                        check.last_result = "Success" if result is not None else "Failed (No response)"
                        if result is None:
                            failed += 1
                            failed_ping_labels.append(check.label)
                    except Exception as e:
                        check.last_checked = now
                        check.last_result = f"Failed ({str(e)})"
                        failed += 1
                        failed_ping_labels.append(check.label)
                if failed == 0:
                    new_status = 'Operational'
                elif failed == 1:
                    new_status = 'Partial Outage'
                else:
                    new_status = 'Major Outage'
                desc = f"Automated check: {failed} of {total_checks} failed (HTTP: {len(enabled_http_checks)}"
                if failed_http_labels:
                    desc += f" ({', '.join(failed_http_labels)})"
                desc += f", Ping: {len(enabled_pings)}"
                if failed_ping_labels:
                    desc += f" ({', '.join(failed_ping_labels)})"
                desc += ")"
                if new_status != server.current_status:
                    current_history = StatusHistory.query.filter_by(server_id=server.id, end_time=None).first()
                    if current_history:
                        current_history.end_time = now
                    history = StatusHistory(
                        server_id=server.id,
                        start_time=now,
                        status=new_status,
                        description=desc,
                        username='system'
                    )
                    db.session.add(history)
                    server.current_status = new_status
                    db.session.commit()
                    app.logger.info(f"Automated status update for {server.name} to {new_status}", extra={'user': 'system', 'action': f'Automated update: {server.name} to {new_status}'})
        time.sleep(300)
# Routes
@app.route('/')
def index():
    from functions.ldap import connect_ldap  # Local import to avoid circular dependency
    servers = Server.query.all()
    today = date.today()
    active_issues = StatusHistory.query.join(Server).filter(
        StatusHistory.end_time == None,
        StatusHistory.status != 'Operational'
    ).all()
    resolved_issues = StatusHistory.query.join(Server).filter(
        StatusHistory.end_time != None,
        StatusHistory.status != 'Operational',
        db.func.date(StatusHistory.end_time) == today
    ).all()
    scheduled_maintenances = ScheduledMaintenance.query.join(Server).filter(
        db.or_(
            db.func.date(ScheduledMaintenance.start_time) == today,
            db.func.date(ScheduledMaintenance.end_time) == today
        )
    ).all()
    # Fetch timeline issues (all status history entries for today)
    timeline_issues = StatusHistory.query.join(Server).filter(
        db.func.date(StatusHistory.start_time) == today
    ).order_by(StatusHistory.start_time.desc()).all()
    # Add relative time and admin full name to each issue
    now = datetime.utcnow()
    for issue in timeline_issues:
        time_diff = now - issue.start_time
        minutes = int(time_diff.total_seconds() / 60)
        if minutes < 60:
            issue.relative_time = f"{minutes} minutes ago"
        elif minutes < 1440:
            hours = minutes // 60
            issue.relative_time = f"{hours} hour{'s' if hours > 1 else ''} ago"
        else:
            days = minutes // 1440
            issue.relative_time = f"{days} day{'s' if days > 1 else ''} ago"
        # Fetch admin full name if username exists and not 'system'
        if issue.username and issue.username != 'system':
            domain = 'vm.be'
            upn = f"{issue.username}@{domain}"
            conn, user_info = connect_ldap(upn, None)
            if user_info:
                issue.admin_name = f"{user_info['first_name']} {user_info['last_name']}"
            else:
                issue.admin_name = issue.username
            if conn:
                conn.unbind()
        else:
            issue.admin_name = 'System'
    statuses = {status.name: {'color': status.color, 'icon': status.icon} for status in Status.query.all()}
    return render_template('index.html', servers=servers, STATUSES=statuses,
                         active_issues=active_issues, resolved_issues=resolved_issues,
                         scheduled_maintenances=scheduled_maintenances, timeline_issues=timeline_issues)

@app.route('/server/<int:server_id>')
def server_details(server_id):
    from functions.ldap import connect_ldap  # Local import to avoid circular dependency
    server = Server.query.get_or_404(server_id)
    histories = StatusHistory.query.filter_by(server_id=server_id).order_by(StatusHistory.start_time.desc()).all()
    maintenances = ScheduledMaintenance.query.filter_by(server_id=server_id).filter(
        (ScheduledMaintenance.end_time > datetime.utcnow()) | (ScheduledMaintenance.is_active == True)
    ).all()
    # Add admin full name to histories
    for history in histories:
        if history.username and history.username != 'system':
            domain = 'vm.be'
            upn = f"{history.username}@{domain}"
            conn, user_info = connect_ldap(upn, None)
            if user_info:
                history.admin_name = f"{user_info['first_name']} {user_info['last_name']}"
            else:
                history.admin_name = history.username
            if conn:
                conn.unbind()
        else:
            history.admin_name = 'System'
    statuses = {status.name: {'color': status.color, 'icon': status.icon} for status in Status.query.all()}
    return render_template('server_details.html', server=server, histories=histories, maintenances=maintenances, STATUSES=statuses)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_authenticated, user_info = authenticate_user(username, password)
        if is_authenticated:
            session['username'] = username
            session['full_name'] = f"{user_info['first_name']} {user_info['last_name']}" if user_info else username
            app.logger.info(f"User {username} logged in", extra={'user': username, 'action': 'Logged in'})
            flash('Logged in successfully.')
            return redirect(url_for('admin'))
        flash('Invalid credentials or insufficient permissions.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    session.pop('username', None)
    session.pop('full_name', None)
    app.logger.info(f"User {username} logged out", extra={'user': username, 'action': 'Logged out'})
    flash('Logged out.')
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    servers = Server.query.all()
    maintenances = ScheduledMaintenance.query.filter(
        (ScheduledMaintenance.end_time > datetime.utcnow()) | (ScheduledMaintenance.is_active == True)
    ).all()
    statuses = {status.name: {'color': status.color, 'icon': status.icon} for status in Status.query.all()}
    return render_template('admin.html', servers=servers, maintenances=maintenances, STATUSES=statuses)

@app.route('/admin/update_status/<int:server_id>', methods=['GET', 'POST'])
@login_required
def update_status(server_id):
    server = Server.query.get_or_404(server_id)
    if request.method == 'POST':
        new_status = request.form['status']
        description = request.form['description']
        
        if not Status.query.filter_by(name=new_status).first():
            flash('Invalid status selected.')
            return redirect(url_for('update_status', server_id=server_id))
        
        current_history = StatusHistory.query.filter_by(server_id=server_id, end_time=None).first()
        if current_history:
            current_history.end_time = datetime.utcnow()
        
        history = StatusHistory(
            server_id=server_id,
            start_time=datetime.utcnow(),
            status=new_status,
            description=description,
            username=session['username']
        )
        db.session.add(history)
        
        server.current_status = new_status
        db.session.commit()
        app.logger.info(f"Updated status for server {server.name} to {new_status} by {session['username']}", extra={'user': session['username'], 'action': f'Updated server status: {server.name} to {new_status}'})
        flash('Status updated.')
        return redirect(url_for('admin'))
    
    statuses = Status.query.all()
    return render_template('update_status.html', server=server, statuses=statuses)

@app.route('/admin/add_server', methods=['GET', 'POST'])
@login_required
def add_server():
    if request.method == 'POST':
        name = request.form['name']
        if Server.query.filter_by(name=name).first():
            flash('Server name already exists.')
        else:
            server = Server(name=name, current_status='Under investigation')
            db.session.add(server)
            db.session.commit()
            app.logger.info(f"Added new server {name}", extra={'user': session['username'], 'action': f'Added server: {name}'})
            flash('Server added.')
            return redirect(url_for('admin'))
    return render_template('add_server.html')

@app.route('/admin/schedule_maintenance/<int:server_id>', methods=['GET', 'POST'])
@login_required
def schedule_maintenance(server_id):
    server = Server.query.get_or_404(server_id)
    if request.method == 'POST':
        start_time = datetime.strptime(request.form['start_time'], '%Y-%m-%dT%H:%M')
        end_time = datetime.strptime(request.form['end_time'], '%Y-%m-%dT%H:%M')
        description = request.form['description']
        
        if end_time <= start_time:
            flash('End time must be after start time.')
        elif start_time < datetime.utcnow():
            flash('Start time must be in the future.')
        else:
            maintenance = ScheduledMaintenance(
                server_id=server_id,
                start_time=start_time,
                end_time=end_time,
                description=description
            )
            db.session.add(maintenance)
            db.session.commit()
            app.logger.info(f"Scheduled maintenance for server {server.name}", extra={'user': session['username'], 'action': f'Scheduled maintenance for server: {server.name} from {start_time} to {end_time}'})
            flash('Maintenance scheduled.')
            return redirect(url_for('admin'))
    
    return render_template('schedule_maintenance.html', server=server)

@app.route('/admin/delete_maintenance/<int:maintenance_id>', methods=['POST'])
@login_required
def delete_maintenance(maintenance_id):
    maintenance = ScheduledMaintenance.query.get_or_404(maintenance_id)
    server = maintenance.server
    if maintenance.is_active:
        current_history = StatusHistory.query.filter_by(server_id=server.id, end_time=None).first()
        if current_history:
            current_history.end_time = datetime.utcnow()
        history = StatusHistory(
            server_id=server.id,
            start_time=datetime.utcnow(),
            status='Operational',
            description='Maintenance cancelled.',
            username=session['username']
        )
        db.session.add(history)
        server.current_status = 'Operational'
    db.session.delete(maintenance)
    db.session.commit()
    app.logger.info(f"Deleted maintenance for server {server.name}", extra={'user': session['username'], 'action': f'Deleted maintenance for server: {server.name}'})
    flash('Maintenance period deleted.')
    return redirect(url_for('admin'))

@app.route('/admin/edit_server/<int:server_id>', methods=['GET', 'POST'])
@login_required
def edit_server(server_id):
    server = Server.query.get_or_404(server_id)
    if request.method == 'POST':
        new_name = request.form['name']
        if Server.query.filter_by(name=new_name).first():
            flash('Server name already exists.')
        else:
            old_name = server.name
            server.name = new_name
            db.session.commit()
            app.logger.info(f"Updated server name from {old_name} to {new_name}", extra={'user': session['username'], 'action': f'Updated server name: {old_name} to {new_name}'})
            flash('Server name updated.')
            return redirect(url_for('admin'))
    return render_template('edit_server.html', server=server)

@app.route('/admin/delete_server/<int:server_id>', methods=['POST'])
@login_required
def delete_server(server_id):
    server = Server.query.get_or_404(server_id)
    server_name = server.name
    
    maintenances = ScheduledMaintenance.query.filter_by(server_id=server_id).all()
    for maint in maintenances:
        db.session.delete(maint)
    
    histories = StatusHistory.query.filter_by(server_id=server_id).all()
    for history in histories:
        db.session.delete(history)
    
    http_checks = HttpCheck.query.filter_by(server_id=server_id).all()
    for check in http_checks:
        db.session.delete(check)
    
    ping_checks = PingCheck.query.filter_by(server_id=server_id).all()
    for check in ping_checks:
        db.session.delete(check)
    
    db.session.delete(server)
    db.session.commit()
    
    app.logger.info(f"Deleted server {server_name}", extra={'user': session['username'], 'action': f'Deleted server: {server_name}'})
    flash('Server deleted successfully.')
    return redirect(url_for('admin'))

@app.route('/admin/manage_statuses', methods=['GET', 'POST'])
@login_required
def manage_statuses():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            status_name = request.form['status_name']
            color = request.form['color']
            icon = request.form.get('icon', None)
            if not status_name or not color:
                flash('Status name and color are required.')
            elif Status.query.filter_by(name=status_name).first():
                flash('Status name already exists.')
            else:
                status = Status(name=status_name, color=color, icon=icon)
                db.session.add(status)
                db.session.commit()
                app.logger.info(f"Added new status {status_name}", extra={'user': session['username'], 'action': f'Added status: {status_name}'})
                flash('Status added.')
        elif action == 'edit':
            status_id = request.form['status_id']
            status = Status.query.get_or_404(status_id)
            new_name = request.form['status_name']
            color = request.form['color']
            icon = request.form.get('icon', None)
            if not new_name or not color:
                flash('Status name and color are required.')
            elif new_name != status.name and Status.query.filter_by(name=new_name).first():
                flash('Status name already exists.')
            else:
                old_name = status.name
                status.name = new_name
                status.color = color
                status.icon = icon
                db.session.commit()
                app.logger.info(f"Updated status from {old_name} to {new_name}", extra={'user': session['username'], 'action': f'Updated status: {old_name} to {new_name}'})
                flash('Status updated.')
        elif action == 'delete':
            status_id = request.form['status_id']
            status = Status.query.get_or_404(status_id)
            if Server.query.filter_by(current_status=status.name).first() or StatusHistory.query.filter_by(status=status.name).first():
                flash('Cannot delete status; it is currently in use.')
            else:
                status_name = status.name
                db.session.delete(status)
                db.session.commit()
                app.logger.info(f"Deleted status {status_name}", extra={'user': session['username'], 'action': f'Deleted status: {status_name}'})
                flash('Status deleted.')
        return redirect(url_for('manage_statuses'))
    
    statuses = Status.query.all()
    available_icons = [
        'fa-solid fa-circle-check', 'fa-solid fa-exclamation-triangle', 'fa-solid fa-plug-circle-exclamation',
        'fa-solid fa-circle-xmark', 'fa-solid fa-circle-question', 'fa-solid fa-wrench', 'fa-solid fa-bell',
        'fa-solid fa-bolt', 'fa-solid fa-gear', 'fa-solid fa-shield'
    ]
    return render_template('manage_statuses.html', statuses=statuses, available_icons=available_icons)

@app.route('/admin/manage_http_checks/<int:server_id>', methods=['GET', 'POST'])
@login_required
def manage_http_checks(server_id):
    server = Server.query.get_or_404(server_id)
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            label = request.form.get('label')
            url = request.form.get('url')
            if not label or not url:
                flash('Label and URL are required.')
            else:
                check = HttpCheck(server_id=server_id, label=label, url=url, enabled=True)
                db.session.add(check)
                db.session.commit()
                app.logger.info(f"Added HTTP check for server {server.name}: {label}", extra={'user': session['username'], 'action': f'Added HTTP check: {label} for {server.name}'})
                flash('HTTP check added.')
        elif action == 'edit':
            check_id = request.form.get('check_id')
            check = HttpCheck.query.get_or_404(check_id)
            if check.server_id != server_id:
                flash('Unauthorized access.')
                return redirect(url_for('admin'))
            label = request.form.get('label')
            url = request.form.get('url')
            if not label or not url:
                flash('Label and URL are required.')
            else:
                old_label = check.label
                old_url = check.url
                check.label = label
                check.url = url
                db.session.commit()
                app.logger.info(f"Edited HTTP check for server {server.name}: {old_label} to {label}, URL: {old_url} to {url}", extra={'user': session['username'], 'action': f'Edited HTTP check: {old_label} to {label} for {server.name}'})
                flash('HTTP check updated.')
        elif action == 'toggle':
            check_id = request.form.get('check_id')
            check = HttpCheck.query.get_or_404(check_id)
            if check.server_id != server_id:
                flash('Unauthorized access.')
                return redirect(url_for('admin'))
            check.enabled = not check.enabled
            db.session.commit()
            app.logger.info(f"Toggled HTTP check for server {server.name}: {check.label} to {'enabled' if check.enabled else 'disabled'}", extra={'user': session['username'], 'action': f'Toggled HTTP check: {check.label} to {"enabled" if check.enabled else "disabled"} for {server.name}'})
            flash('HTTP check toggled.')
        elif action == 'delete':
            check_id = request.form.get('check_id')
            check = HttpCheck.query.get_or_404(check_id)
            if check.server_id != server_id:
                flash('Unauthorized access.')
                return redirect(url_for('admin'))
            db.session.delete(check)
            db.session.commit()
            app.logger.info(f"Deleted HTTP check for server {server.name}: {check.label}", extra={'user': session['username'], 'action': f'Deleted HTTP check: {check.label} for {server.name}'})
            flash('HTTP check deleted.')
        return redirect(url_for('manage_http_checks', server_id=server_id))
    checks = HttpCheck.query.filter_by(server_id=server_id).all()
    return render_template('manage_http_checks.html', server=server, checks=checks)

@app.route('/admin/manage_ping_checks/<int:server_id>', methods=['GET', 'POST'])
@login_required
def manage_ping_checks(server_id):
    server = Server.query.get_or_404(server_id)
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            label = request.form.get('label')
            hostname = request.form.get('hostname')
            if not label or not hostname:
                flash('Label and hostname are required.')
            else:
                check = PingCheck(server_id=server_id, label=label, hostname=hostname, enabled=True)
                db.session.add(check)
                db.session.commit()
                app.logger.info(f"Added ping check for server {server.name}: {label}", extra={'user': session['username'], 'action': f'Added ping check: {label} for {server.name}'})
                flash('Ping check added.')
        elif action == 'toggle':
            check_id = request.form.get('check_id')
            check = PingCheck.query.get_or_404(check_id)
            if check.server_id != server_id:
                flash('Unauthorized access.')
                return redirect(url_for('admin'))
            check.enabled = not check.enabled
            db.session.commit()
            app.logger.info(f"Toggled ping check for server {server.name}: {check.label} to {'enabled' if check.enabled else 'disabled'}", extra={'user': session['username'], 'action': f'Toggled ping check: {check.label} to {"enabled" if check.enabled else "disabled"} for {server.name}'})
            flash('Ping check toggled.')
        elif action == 'delete':
            check_id = request.form.get('check_id')
            check = PingCheck.query.get_or_404(check_id)
            if check.server_id != server_id:
                flash('Unauthorized access.')
                return redirect(url_for('admin'))
            db.session.delete(check)
            db.session.commit()
            app.logger.info(f"Deleted ping check for server {server.name}: {check.label}", extra={'user': session['username'], 'action': f'Deleted ping check: {check.label} for {server.name}'})
            flash('Ping check deleted.')
        return redirect(url_for('manage_ping_checks', server_id=server_id))
    checks = PingCheck.query.filter_by(server_id=server_id).all()
    return render_template('manage_ping_checks.html', server=server, checks=checks)

@app.route('/admin/force_check/<check_type>/<int:check_id>', methods=['POST'])
@login_required
def force_check(check_type, check_id):
    if check_type not in ['http', 'ping']:
        flash('Invalid check type.')
        return redirect(url_for('admin'))
    
    now = datetime.utcnow()
    if check_type == 'http':
        check = HttpCheck.query.get_or_404(check_id)
        check_type_name = 'HTTP'
        server = check.server
        try:
            resp = requests.get(check.url, timeout=10)
            check.last_checked = now
            check_result = resp.status_code == 200
            check.last_result = f"Success (Status: {resp.status_code})" if check_result else f"Failed (Status: {resp.status_code})"
        except requests.exceptions.RequestException as e:
            check.last_checked = now
            check_result = False
            check.last_result = f"Failed ({str(e)})"
    else:  # ping
        check = PingCheck.query.get_or_404(check_id)
        check_type_name = 'Ping'
        server = check.server
        try:
            result = ping(check.hostname, timeout=2)
            check.last_checked = now
            check_result = result is not None
            check.last_result = "Success" if check_result else "Failed (No response)"
        except Exception as e:
            check.last_checked = now
            check_result = False
            check.last_result = f"Failed ({str(e)})"
    
    # Update server status based on all enabled checks
    enabled_http_checks = [c for c in server.http_checks if c.enabled]
    enabled_pings = [c for c in server.ping_checks if c.enabled]
    total_checks = len(enabled_http_checks) + len(enabled_pings)
    
    if total_checks == 0:
        flash('No enabled checks for this server.')
        return redirect(url_for(f'manage_{check_type}_checks', server_id=server.id))
    
    active_maint = ScheduledMaintenance.query.filter_by(server_id=server.id, is_active=True).first()
    if active_maint:
        flash('Cannot run checks during active maintenance.')
        return redirect(url_for(f'manage_{check_type}_checks', server_id=server.id))
    
    failed = 0
    failed_http_labels = []
    failed_ping_labels = []
    for http_check in enabled_http_checks:
        if http_check.id == check_id and check_type == 'http':
            if not check_result:
                failed += 1
                failed_http_labels.append(http_check.label)
        else:
            try:
                resp = requests.get(http_check.url, timeout=10)
                http_check.last_checked = now
                http_check.last_result = f"Success (Status: {resp.status_code})" if resp.status_code == 200 else f"Failed (Status: {resp.status_code})"
                if resp.status_code != 200:
                    failed += 1
                    failed_http_labels.append(http_check.label)
            except requests.exceptions.RequestException as e:
                http_check.last_checked = now
                http_check.last_result = f"Failed ({str(e)})"
                failed += 1
                failed_http_labels.append(http_check.label)
    
    for ping_check in enabled_pings:
        if ping_check.id == check_id and check_type == 'ping':
            if not check_result:
                failed += 1
                failed_ping_labels.append(ping_check.label)
        else:
            try:
                result = ping(ping_check.hostname, timeout=2)
                ping_check.last_checked = now
                ping_check.last_result = "Success" if result is not None else "Failed (No response)"
                if result is None:
                    failed += 1
                    failed_ping_labels.append(ping_check.label)
            except Exception as e:
                ping_check.last_checked = now
                ping_check.last_result = f"Failed ({str(e)})"
                failed += 1
                failed_ping_labels.append(ping_check.label)
    
    if failed == 0:
        new_status = 'Operational'
    elif failed == 1:
        new_status = 'Partial Outage'
    else:
        new_status = 'Major Outage'
    
    desc = f"Manual {check_type_name} check for {check.label}: {'Success' if check_result else 'Failed'} ({failed} of {total_checks} failed, HTTP: {len(enabled_http_checks)}"
    if failed_http_labels:
        desc += f" ({', '.join(failed_http_labels)})"
    desc += f", Ping: {len(enabled_pings)}"
    if failed_ping_labels:
        desc += f" ({', '.join(failed_ping_labels)})"
    desc += ")"
    
    if new_status != server.current_status:
        current_history = StatusHistory.query.filter_by(server_id=server.id, end_time=None).first()
        if current_history:
            current_history.end_time = now
        history = StatusHistory(
            server_id=server.id,
            start_time=now,
            status=new_status,
            description=desc,
            username=session['username']
        )
        db.session.add(history)
        server.current_status = new_status
    
    db.session.commit()
    app.logger.info(f"Manual {check_type_name} check for server {server.name}: {check.label} - {'Success' if check_result else 'Failed'}", extra={'user': session['username'], 'action': f'Manual {check_type_name} check: {check.label} for {server.name}'})
    flash(f"{check_type_name} check completed: {check.last_result}")
    return redirect(url_for(f'manage_{check_type}_checks', server_id=server.id))

# Create database if not exists
if not os.path.exists('status.db'):
    with app.app_context():
        db.create_all()
        if not Status.query.first():
            default_statuses = [
                ('Operational', '#10b981', 'fa-solid fa-circle-check'),
                ('Performance Issues', '#f59e0b', 'fa-solid fa-exclamation-triangle'),
                ('Partial Outage', '#f59e0b', 'fa-solid fa-plug-circle-exclamation'),
                ('Major Outage', '#ef4444', 'fa-solid fa-circle-xmark'),
                ('Under investigation', '#06b6d4', 'fa-solid fa-circle-question'),
                ('Under Maintenance', '#f59e0b', 'fa-solid fa-wrench'),
                ('Identified', '#f59e0b', 'fa-solid fa-bell'),
                ('Investigating', '#06b6d4', 'fa-solid fa-circle-question'),
                ('Fixed', '#10b981', 'fa-solid fa-circle-check')
            ]
            for name, color, icon in default_statuses:
                status = Status(name=name, color=color, icon=icon)
                db.session.add(status)
                app.logger.info(f"Added default status {name}", extra={'user': 'system', 'action': f'Added default status: {name}'})
            db.session.commit()
        if not Server.query.first():
            default_servers = ['SERVER1', 'SERVER2', 'SERVER3', 'SERVER4', 'SERVER5', 'SERVER6', 'SERVER7']
            for name in default_servers:
                server = Server(name=name, current_status='Operational')
                db.session.add(server)
                app.logger.info(f"Added default server {name}", extra={'user': 'system', 'action': f'Added default server: {name}'})
            db.session.commit()

# Threaded background tasks
scheduler_thread = threading.Thread(target=maintenance_scheduler, args=(app,), daemon=True)
scheduler_thread.start()
server_checker_thread = threading.Thread(target=server_checker, args=(app,), daemon=True)
server_checker_thread.start()

if __name__ == '__main__':
    # app.run(debug=False)
    print(app.url_map)
    from waitress import serve
    with app.app_context(): # Create application context
        print(app.url_map)
    serve(app, host="0.0.0.0", port=80)
