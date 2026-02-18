# CloudsineAI WebTest Solution

This repository now contains a complete Flask web app that:
- uploads files from a browser,
- scans them with VirusTotal,
- shows scan verdicts and engine detections,
- and uses Gemini to explain results for non-technical users.

## Stack
- Backend: Python + Flask
- Frontend: HTML/CSS/Vanilla JS
- Deployment: gunicorn + nginx + systemd (EC2)

## Project structure
- `app/main.py`: Flask routes and input validation
- `app/virustotal.py`: VirusTotal API client and result normalization
- `app/genai.py`: Gemini API client for natural-language explanations
- `templates/index.html`: Upload UI
- `static/app.js`: Browser logic for scan and explain workflow
- `deploy/webtest.service`: systemd service template
- `deploy/nginx-webtest.conf`: nginx reverse proxy config

## Local setup
1. Create and activate a venv:
```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```
2. Install deps:
```bash
pip install -r requirements.txt
```
3. Add environment variables:
```bash
cp .env.example .env
# Fill in VT_API_KEY and GEMINI_API_KEY
```
4. Run app:
```bash
python run.py
```
5. Open `http://localhost:8000`

## API endpoints
- `GET /health`: health check
- `POST /api/scan`: multipart upload (`file`)
- `POST /api/explain`: JSON body with `summary`

## Security notes
- Upload size limit via `MAX_UPLOAD_MB`
- Extension allowlist in `app/main.py`
- Filenames sanitized with `secure_filename`
- Files are processed in memory; no execution path

## EC2 deployment (Ubuntu)
1. SSH to instance and install packages:
```bash
sudo apt update
sudo apt install -y python3-venv python3-pip nginx
```
2. Clone repo and set up app:
```bash
git clone <your-repo-url> webtest
cd webtest
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env with your API keys
```
3. Configure systemd:
```bash
sudo cp deploy/webtest.service /etc/systemd/system/webtest.service
sudo systemctl daemon-reload
sudo systemctl enable webtest
sudo systemctl start webtest
sudo systemctl status webtest
```
4. Configure nginx:
```bash
sudo cp deploy/nginx-webtest.conf /etc/nginx/sites-available/webtest
sudo ln -s /etc/nginx/sites-available/webtest /etc/nginx/sites-enabled/webtest
sudo nginx -t
sudo systemctl restart nginx
```
5. Ensure EC2 Security Group allows inbound `80` (and `22` for SSH).

## Testing with provided sample files
Use files under `files/` in the web UI and verify:
- scan stats populate,
- malicious engine detections are listed,
- explanation button returns a plain-English summary.

