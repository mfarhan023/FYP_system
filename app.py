import os
import io
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from dotenv import load_dotenv
from analyzer_engine import AnalyzerEngine, weighted_heuristic_score
from db_logger import DbLogger

# Load .env file for local development (ignored in production/Vercel)
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'ezveri-phish-secret-2024')

engine = AnalyzerEngine()
logger = DbLogger()


@app.route('/')
def index():
    return render_template('index.html')


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
        heuristic = weighted_heuristic_score(result['urls_found'], email_text)
        result['heuristic_label']     = heuristic['final_label']
        result['heuristic_score']     = heuristic['total_score']
        result['triggered_features']  = heuristic['triggered_features']
        # Promote label to 'Suspicious' if heuristic says so
        if heuristic['final_label'] == 'Suspicious':
            result['label'] = 'Suspicious'
    else:
        result['heuristic_label']    = None
        result['heuristic_score']    = None
        result['triggered_features'] = []
    # ───────────────────────────────────────────────────────────────────

    analysis_id = logger.log_result(result)
    result['id'] = analysis_id
    session['last_result'] = result
    return redirect(url_for('result', analysis_id=analysis_id))


@app.route('/result/<int:analysis_id>')
def result(analysis_id):
    stored = logger.get_analysis_by_id(analysis_id)
    if stored:
        return render_template('result.html', result=stored)
    result_data = session.get('last_result')
    if result_data and result_data.get('id') == analysis_id:
        return render_template('result.html', result=result_data)
    flash('Analysis not found.', 'error')
    return redirect(url_for('index'))


@app.route('/history')
def history():
    analyses = logger.get_all_analyses()
    stats = logger.get_stats()
    return render_template('history.html', analyses=analyses, stats=stats)


@app.route('/export')
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
def delete_analysis(analysis_id):
    try:
        logger.delete_analysis(analysis_id)
        flash('Record deleted successfully.', 'success')
    except Exception as e:
        flash(f'Error: {e}', 'error')
    return redirect(url_for('history'))


if __name__ == '__main__':
    app.run(debug=True, port=5000)
