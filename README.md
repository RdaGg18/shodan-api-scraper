# Shodan API Key Scraper

A simple python script for finding exposed Shodan API Keys using Github Code Search API

## Description

A Python script that searches GitHub repositories for exposed Shodan API keys, validates them against the Shodan API, and exports verified keys to a JSON file.

## Getting Started
### Prerequisites
* Python 3.7+
* Valid [Github PAT](https://github.com/settings/tokens) (no scopes needed, public code search only)
* [github3.py](https://pypi.org/project/github3.py/) library
* [shodan](https://pypi.org/project/shodan/) library

### Installing
1. **Clone the repository**
```bash
git clone https://github.com/RdaGg18/shodan-api-scraper.git
cd shodan-api-scraper
```

2. **Install Prerequisites**
```bash
python -m venv venv                         # Build a virtual environment first
pip install shodan github3.py python-dotenv # Install the requirements
```

3. **Insert Credentials**
- Put your [Github PAT](https://github.com/settings/tokens) into `.env`
- **Make sure to add `.env` to your `.gitignore`**
- Example `.env`:
```.env
# Insert your PAT here
GITHUB_PAT = ghp_************************************
```

### Starting the search
- **Run the Program**
```bash
python main.py
```

- **Example Outputs**:
```bash
[01/11/2026 16:44:30]-[INFO] Starting Query language:python sd=shodan(
...
[01/11/2026 16:55:31]-[INFO] Found ... results!
[01/11/2026 16:55:31]-[INFO] Fetching files...
...
[01/11/2026 17:19:39]-[DEBUG] API Key: ****************************** invalid
```

## Responsible use
⚠️ Important: This tool is for educational and research purposes only!

- ✅ Report discovered keys to their owners and to Shodan so they can be rotated.
- ✅ Uses read-only API endpoints
- ✅ Respects rate limits and timeouts
- ❌ Never use, sell, or store third-party keys you are not authorised to access.

Please use responsibly and respect others' infrastructure! 🤝

## License
This project is licensed under the MIT License - see the LICENSE file for details

## Acknowledgments
- [ShodanHound](https://github.com/damanoreshkan-beep/ShodanHound)
- [DomPizzie](https://gist.github.com/DomPizzie/7a5ff55ffa9081f2de27c315f5018afc)
