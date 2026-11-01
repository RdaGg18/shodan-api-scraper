from shodan   import Shodan, exception
from datetime import datetime, timedelta
from time     import time, sleep
from dotenv   import load_dotenv

import logging
import github3 as gh
import re
import json
import os

load_dotenv()

main_log = logging.getLogger(__name__)
main_log.setLevel(logging.DEBUG)

format = logging.Formatter(
    fmt='[{asctime}]-[{levelname}] {message}',
    datefmt="%d/%m/%Y %H:%M:%S",
    style='{'
)

console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(format)

file = logging.FileHandler(f'logs/{datetime.fromtimestamp(time()).strftime("%d-%m-%Y_%H-%M-%S")}.log', mode='a')
console.setLevel(logging.DEBUG)
file.setFormatter(format)

main_log.addHandler(console)
main_log.addHandler(file)

MIN_CREDITS = 10
MAX_RESULTS = 10 # Set to -1 for all results

REGEX       = re.compile(r'(?<![A-Za-z0-9])[A-Za-z0-9]{32}(?![A-Za-z0-9])') #idk this regex jst copied it from google
OUTPUT_FILE = "found_keys.json"

with open('./shodan_settings/query_keywords.txt', 'r') as f:
    query_lists = f.read().splitlines()

with open('./shodan_settings/search_scope.txt', 'r') as f:
    scopes = f.read().splitlines()

GITHUB_API = os.getenv("GITHUB_PAT", "PLEASE_SET_YOUR_PAT")

known_keys = []
if os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, 'r') as f:
        raw_data = json.load(f)
        known_keys = [(d.get('key', ""), d.get('date_found', "")) for d in raw_data] # 0: key, 1: date found, 2: date updated

def get_credits(shodan_key: str) -> tuple:
    api = Shodan(shodan_key)

    try:
        api_info      = api.info()
        scan_credits  = api_info.get('scan_credits', 0)
        query_credits = api_info.get('query_credits', 0)

        sleep(1)

        return scan_credits, query_credits

    except exception.APIError as e:
        sleep(1)
        if e.value == "Invalid API key":
            main_log.debug(f"API Key: {shodan_key} invalid")
            return 0, 0
        else:
            main_log.warning(f"Unknown error: {e}, key: {shodan_key}")
            return 0, 0
    
    except Exception as e:
        sleep(1)
        main_log.error(f"Shodan Key({shodan_key}) Error: {e}")
        return 0, 0

def search_github(github_object, query):
    list_result = []

    try:
        results = github_object.search_code(query, number=MAX_RESULTS)
        for result in results:
            if result:
                list_result.append((result.repository, result.path))
                sleep(1)
                
    except gh.exceptions.ForbiddenError as e:
        main_log.warning(f"Ratelimited with error: {e}!")

        limit = github_object.rate_limit()
        reset = limit['resources']['code_search']['reset']
        reset_time = max(0, reset - int(time())) + 5
        
        main_log.info(f"Sleeping for {reset_time} sec...")
        sleep(reset_time)

    except Exception as e:
        main_log.error(f"Unknown Error: {e}")
    
    return list_result

def get_github_file(github_object, repo_owner, repo_name, file_path, max_retry: int = 3):
    for attempt in range(max_retry):
        try:
            repository = github_object.repository(repo_owner, repo_name)
            file_object = repository.file_contents(file_path)
            file_decoded = file_object.decoded.decode('utf-8')

            return file_decoded
        
        except Exception as e:
            main_log.error(f"Error: {e}")
            if attempt + 1 == max_retry:
                main_log.warning(f"Max Retry reached. Skipping {repo_owner}/{repo_name}...", 1)

                return ""
            
            main_log.info(f"Retrying in {2 ** attempt} Second...")
            sleep(2 ** attempt)

def main():
    uv_results = [] #unverified results
    uv_files   = [] #unverified files
    uv_tokens  = [] #unverified tokens
    ver_tokens = [] #verified tokens
    github = gh.login(token=GITHUB_API)

    for scope in scopes:
        for query in query_lists: # loops through all combinations of the full query, and added the result to uv_results
            full_query     = f'{scope} {query}'
            search_result  = search_github(github, full_query)
            main_log.info(f"Starting Query {full_query}")
            
            for r in search_result:
                uv_results.append(r)
                sleep(1)

            sleep(1)

    total = len(uv_results)

    main_log.info(f"Found {total} results!")

    main_log.info("Fetching files...")
    for uv_result in uv_results:
        repo_res_name = uv_result[0].name
        repo_author   = uv_result[0].owner.login
        file_path     = uv_result[1]

        uv_files.append(get_github_file(github, repo_author, repo_res_name, file_path))

    for uv_file in uv_files:
        file_tokens = re.findall(REGEX, uv_file)
        for file_token in file_tokens:
            uv_tokens.append(file_token)

    total = len(uv_tokens)
    seen_keys = set()

    for uv_token in uv_tokens:
        if uv_token in seen_keys or uv_token in known_keys: continue
        seen_keys.add(uv_token)
        sleep(1)

        scan_credit, query_credit = get_credits(uv_token)

        if scan_credit >= MIN_CREDITS or query_credit >= MIN_CREDITS:
            main_log.info(f"Found token {uv_token}!")
            ver_tokens.append((uv_token, datetime.fromtimestamp(time()).strftime("%d/%m/%Y %H:%M:%S")))
            sleep(1)
        else:
            sleep(1)
            continue

    tokens = ver_tokens + known_keys

    parsed_tokens = []
    for token, date_found in tokens:
        scan_credit, query_credit = get_credits(token[0])
        sleep(3)
        token_dict = {
            "key": token,
            "scan_credits": scan_credit,
            "query_credits": query_credit,
            "date_found": date_found,
            "date_updated": datetime.fromtimestamp(time()).strftime("%d/%m/%Y %H:%M:%S")
        }

        parsed_tokens.append(token_dict)

    print(f"Found {len(ver_tokens)}, all found tokens: {",".join([i['key'] for i in parsed_tokens])}")

    with open(OUTPUT_FILE, 'w') as f:
        json.dump(list(parsed_tokens), f, indent=4)

if __name__ == '__main__':
    main()