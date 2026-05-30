import os
import io
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from dotenv import load_dotenv
from analyzer_engine import AnalyzerEngine
from heuristic_scorer import WeightedHeuristicScorer
from db_logger import DbLogger

# Load .env file for local development (ignored in production/Vercel)
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'ezveri-phish-secret-2024')

engine = AnalyzerEngine()
heuristic_scorer = WeightedHeuristicScorer()
try:
    logger = DbLogger()
except Exception as _db_err:
    import sys
    print(f"[STARTUP ERROR] DbLogger failed: {_db_err}", file=sys.stderr)
    logger = None


# ── Admin Auth Helper ──────────────────────────────────────────────────────────

def admin_required(f):
    """Decorator: return 404 silently if not authenticated as admin.
    Regular users see no indication that an admin panel exists.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            return render_template('404.html'), 404
        return f(*args, **kwargs)
    return decorated


# ── Admin Auth Routes ──────────────────────────────────────────────────────────

# Secret admin URL — not linked anywhere in the UI.
# Only the admin knows this URL exists.
@app.route('/ezveri-ctrl-2024', methods=['GET', 'POST'])
def admin_login():
    # Already logged in — redirect to history
    if session.get('is_admin'):
        return redirect(url_for('history'))

    error = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        admin_pw = os.environ.get('ADMIN_PASSWORD', 'admin1234')
        if password == admin_pw:
            session['is_admin'] = True
            flash('Logged in as Admin.', 'success')
            return redirect(url_for('history'))
        else:
            error = 'Incorrect password. Please try again.'

    return render_template('admin_login.html', error=error)


@app.route('/ezveri-ctrl-2024/logout')
def admin_logout():
    session.pop('is_admin', None)
    flash('Logged out from admin session.', 'success')
    return redirect(url_for('index'))


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# ── Public Routes ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/debug-env')
def debug_env():
    """Temporary debug route — shows env var status and DB connectivity. Remove after fix."""
    import sys
    db_url = os.environ.get('DATABASE_URL', '')
    db_status = 'logger is None (failed to init)' if logger is None else 'logger OK'
    return {
        'DATABASE_URL': 'SET' if db_url else 'MISSING',
        'DATABASE_URL_prefix': db_url[:30] + '...' if db_url else '',
        'SECRET_KEY': 'SET' if os.environ.get('SECRET_KEY') else 'MISSING',
        'ADMIN_PASSWORD': 'SET' if os.environ.get('ADMIN_PASSWORD') else 'MISSING',
        'db_logger_status': db_status,
        'python_version': sys.version,
    }


@app.route('/analyze', methods=['POST'])
def analyze():
    email_text = request.form.get('email_content', '').strip()
    if not email_text:
        flash('Please paste some email content to analyze.', 'warning')
        return redirect(url_for('index'))
    if len(email_text) < 5:
        flash('Content is too short. Please provide more text.', 'warning')
        return redirect(url_for('index'))

    result = engine.analyze(email_text)

    # ── Heuristic fallback ──────────────────────────────────────────────
    # Only run the weighted heuristic scorer if the blacklist found nothing.
    # If blacklisted, the label stays 'Confirmed Phishing' and we skip this.
    if result['blacklisted_count'] == 0:
        heuristic = heuristic_scorer.score(email_text, result['urls_found'])
        result['heuristic_label']     = heuristic['label']
        result['heuristic_score']     = heuristic['score']
        result['triggered_features']  = heuristic['triggered_features']
        # Heuristic can only promote label to 'Suspicious'.
        # 'Confirmed Phishing' is reserved EXCLUSIVELY for PhishTank blacklist matches.
        if heuristic['label'] in ('Suspicious', 'Confirmed Phishing'):
            result['label'] = 'Suspicious'
    else:
        result['heuristic_label']    = None
        result['heuristic_score']    = None
        result['triggered_features'] = []
    # ───────────────────────────────────────────────────────────────────

    if logger is None:
        flash('Database not configured. Please contact the administrator.', 'error')
        return redirect(url_for('index'))

    analysis_id = logger.log_result(result)
    result['id'] = analysis_id
    session['last_result'] = result
    return redirect(url_for('result', analysis_id=analysis_id))


@app.route('/result/<int:analysis_id>')
def result(analysis_id):
    stored = logger.get_analysis_by_id(analysis_id)
    if stored:
        last_result = session.get('last_result')
        if last_result and last_result.get('id') == analysis_id:
            if stored.get('heuristic_score') is None and last_result.get('heuristic_score') is not None:
                stored['heuristic_score'] = last_result['heuristic_score']
            if stored.get('heuristic_label') is None and last_result.get('heuristic_label') is not None:
                stored['heuristic_label'] = last_result['heuristic_label']
            if not stored.get('triggered_features') and last_result.get('triggered_features'):
                stored['triggered_features'] = last_result['triggered_features']
        return render_template('result.html', result=stored)
    result_data = session.get('last_result')
    if result_data and result_data.get('id') == analysis_id:
        return render_template('result.html', result=result_data)
    flash('Analysis not found.', 'error')
    return redirect(url_for('index'))


# ── Admin-Only Routes ──────────────────────────────────────────────────────────

@app.route('/history')
@admin_required
def history():
    analyses = logger.get_all_analyses()
    stats = logger.get_stats()
    return render_template('history.html', analyses=analyses, stats=stats)


@app.route('/export')
@admin_required
def export():
    content = logger.export_csv_content()
    if not content:
        flash('No records to export.', 'warning')
        return redirect(url_for('history'))
    return send_file(
        io.BytesIO(content.encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='ezveri_log.csv'
    )


@app.route('/delete/<int:analysis_id>', methods=['POST'])
@admin_required
def delete_analysis(analysis_id):
    try:
        logger.delete_analysis(analysis_id)
        flash('Record deleted successfully.', 'success')
    except Exception as e:
        flash(f'Error: {e}', 'error')
    return redirect(url_for('history'))


if __name__ == '__main__':
    app.run(debug=True, port=5000)
