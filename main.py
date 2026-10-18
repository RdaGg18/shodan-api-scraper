from shodan   import Shodan
from datetime import datetime, timedelta
from time     import time, sleep
from dotenv   import load_dotenv

import github3 as gh
import re
import json
import os

load_dotenv()

MIN_CREDITS = 10
MAX_RESULTS = 200

REGEX       = re.compile(r'(?<![A-Za-z0-9])[A-Za-z0-9]{32}(?![A-Za-z0-9])') #idk this regex jst copied it from google
OUTPUT_FILE = "found_keys.json"

with open('./shodan_settings/query_keywords.txt', 'r') as f:
    query_lists = f.read().splitlines()

with open('./shodan_settings/search_scope.txt', 'r') as f:
    scopes = f.read().splitlines()

GITHUB_API = os.getenv("GITHUB_PAT", "PLEASE_SET_YOUR_PAT")

raw_data   = []
known_keys = []
if os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, 'r') as f:
        raw_data = json.load(f)
        known_keys = [d['key'] for d in raw_data]

def log(message, message_type=0):
    """0: Info, 1: Error"""

    t   = time()
    dto = datetime.fromtimestamp(t)
    fd  = dto.strftime("%d/%m/%Y %H:%M:%S")

    if message_type == 0: print(f'[{fd}]-[*] {message}')
    if message_type == 1: print(f'[{fd}]-[!] {message}')

def calc_eta(last_time, current_data, total_data):
    elapsed_time = max(0.1, time() - last_time)
    percent_comp = current_data / total_data * 100
    data_per_sec = current_data / elapsed_time
    time_remains = (total_data - current_data) / data_per_sec

    return percent_comp, time_remains

def print_eta(name, last_time, current_data, total_data):
    print(" " * 99, end='\r', flush=True) #cleans it so there's no number after
    percent, eta = calc_eta(last_time, current_data, total_data)
    print(f"{name}: {percent:.2f}%, ETA: {timedelta(seconds=int(eta))}", end='\r', flush=True)

def get_credits(shodan_key: str) -> tuple:
    api = Shodan(shodan_key)

    try:
        api_info      = api.info()
        scan_credits  = api_info.get('scan_credits', 0)
        query_credits = api_info.get('query_credits', 0)

        return scan_credits, query_credits
    
    except Exception as e:
        log(f"Shodan Key({shodan_key}) Error: {e}", 1)
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
        log(f"Ratelimited with error: {e}!", 1)

        limit = github_object.rate_limit()
        reset = limit['resources']['code_search']['reset']
        reset_time = max(0, reset - int(time())) + 5
        
        log(f"Sleeping for {reset_time} sec...")
        sleep(reset_time)

    except Exception as e:
        log(f"Unknown Error: {e}", 1)
    
    return list_result

def get_github_file(github_object, repo_owner, repo_name, file_path):
    repository = github_object.repository(repo_owner, repo_name)
    file_object = repository.file_contents(file_path)
    file_decoded = file_object.decoded.decode('utf-8')

    return file_decoded

def main():
    uv_results = [] #unverified results
    uv_files   = [] #unverified files
    uv_tokens  = [] #unverified tokens
    ver_tokens = [] #verified tokens
    github = gh.login(token=GITHUB_API)

    max_query     = len(scopes) * len(query_lists)
    current_fetch = 0
    current_query = 0

    time_bfl = time() #time before loop

    for scope in scopes:
        for query in query_lists: #loops through all combinations of the full query, and added the result to uv_results
            current_query += 1
            full_query     = f'{scope} {query}'
            search_result  = search_github(github, full_query)
            
            for r in search_result:
                current_fetch  += 1
                fetch_per_query = current_fetch / current_query

                print_eta("Search Loop", time_bfl, current_fetch, max_query * fetch_per_query)

                uv_results.append(r)
                sleep(1)

            print_eta("Github Query", time_bfl, current_query, max_query)
            sleep(1)

    total = len(uv_results)

    time_bfl = time()

    for i, uv_result in enumerate(uv_results, start=1):
        print_eta("Load File", time_bfl, i, total)
        
        repo_res_name = uv_result[0].name
        repo_author   = uv_result[0].owner.login
        file_path     = uv_result[1]

        uv_files.append(get_github_file(github, repo_author, repo_res_name, file_path))

    for uv_file in uv_files:
        file_tokens = re.findall(REGEX, uv_file)
        for file_token in file_tokens:
            uv_tokens.append(file_token)

    last_time = time()
    total = len(uv_tokens)
    seen_keys = set()

    for i, uv_token in enumerate(uv_tokens, start=1):
        if uv_token in seen_keys or uv_token in known_keys: continue
        seen_keys.add(uv_token)
        sleep(1)

        print_eta("Key Checking", last_time, i, total)

        scan_credit, query_credit = get_credits(uv_token)

        if scan_credit >= MIN_CREDITS or query_credit >= MIN_CREDITS:
            log(f"Found token {uv_token}")
            ver_tokens.append({"key": uv_token, "scan_credit": scan_credit, "query_credit": query_credit})
            sleep(1)
        else:
            sleep(1)
            continue

    all_tokens = ver_tokens + list(raw_data)

    print(f"Found {len(ver_tokens)}, all found tokens: {all_tokens}")

    with open(OUTPUT_FILE, 'w') as f:
        json.dump(list(all_tokens), f, indent=4)

log('running')
main()