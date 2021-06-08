import json, requests, sseclient, sys, urllib3, re, tempfile

from bs4 import BeautifulSoup
from pathlib import Path
from http import cookiejar

proxies = {"http": "", "https": ""}

def extract_auth_token(cookiejar, response):
    """extract auth token from local cookie file"""
    auth_token = None
    concourse_cookies = ["skymarshal_auth0", "skymarshal_auth"]
    for concourse_cookie in concourse_cookies:
        for cookie in cookiejar:
            if cookie.name == concourse_cookie:
                auth_token = cookie.value.strip('"').split(' ')[1]
                break
    if not auth_token:
        raise Exception(
            "\x1b[31m Could not retrieve token {} from cookie\x1b[0m\ncurrent cookies: {}".format(
                " or ".join(concourse_cookies), cookiejar
            )
        )
    # Concourse truncated any cookies larger than 4000 bytes down to exactly 4000. Once you strip off the 'bearer ' part off the cookie, that leaves 3993 of truncated token.
    # As the truncated cookie does not work, we now try a fallback technique to get the cookie directly from the HTML response that concourse sends.
    # The response contains a <script> tag which includes the authToken, so we use BeautifulSoup and some regex to extract the token instead.
    if len(auth_token) >= 3993:
        soup = BeautifulSoup(response.content, features="html.parser")
        scripts=soup.find_all('script')
        for script in scripts:
            if script.get('src') == None:
                script_contents=script.string
                auth_token=re.search(r'(authToken:\ \"bearer\ )(.*)\"', script_contents, re.IGNORECASE).group(2)
    return auth_token


def get_auth_paths(login_html):
    """Parse the concourse login page html and return any auth paths (either be 2 paths LDAP+Local, or just local)"""
    soup = BeautifulSoup(login_html, features="html.parser")
    auth_paths = []
    if soup.find('form'):
        auth_paths.append(soup.find('form').get('action'))
    else:
        form_rows = soup.find_all(class_="theme-form-row")
        for form_row in form_rows:
            if form_row.find('a')['href']:
                auth_paths.append(form_row.find('a')['href'])
    return(auth_paths)

def get_auth_token(api_target, concourse_username, concourse_password):
    cookie_file = tempfile.NamedTemporaryFile()
    cj = cookiejar.LWPCookieJar(cookie_file.name)
    s = requests.Session()
    s.cookies = cj
    login_html = s.get(api_target+"/login", proxies=proxies, verify=False)
    if login_html.status_code != 200:
        print("Could not get login page from concourse.. Bailing")
        sys.exit(1)
    auth_paths = get_auth_paths(login_html.content)
    # If available, ldap auth will be first item in the list, and if not it'll be local auth
    if 'ldap' in auth_paths[0]:
        username = concourse_username
        password = concourse_password
    else:
        print("Concourse is not using LDAP authentication, aborting ...")
        sys.exit(1)
    auth_url = "{}/{}".format(api_target, auth_paths[0].lstrip('/'))
    auth_payload = {
        'login': username,
        'password': password
    }
    r = s.post(auth_url, data=auth_payload, verify=False)
    if 'csrf_token' not in r.url:
        print("Failed to do concourse authentication... Aborting")
        sys.exit(1)
    return extract_auth_token(cj, r)

def search_ids_names(current_id, accum_dict, plan):
    if 'id' in plan:
        current_id = plan['id']
    if 'name' in plan:
        accum_dict[current_id] = plan['name']

    for v in list(plan.values()):
        if type(v) == dict:
            search_ids_names(current_id, accum_dict, v)
        if type(v) == list:
            for v2 in v:
                search_ids_names(current_id, accum_dict, v2)

    return accum_dict

def main():
    requests.packages.urllib3.disable_warnings()

    # variables are env vars from a 'get' or 'put' concourse container
    concourse_hostname = sys.argv[1]
    concourse_username = sys.argv[2]
    concourse_password = sys.argv[3]
    build_number = sys.argv[4]
    log_max_length = int(sys.argv[5])

    token = get_auth_token(concourse_hostname, concourse_username, concourse_password)

    # Resolve taskid's to names
    url = '{0}/api/v1/builds/{1}/plan'.format(concourse_hostname, build_number)
    headers = {
        'Authorization': 'Bearer {0}'.format(token)
    }
    response = requests.get(url, verify=False, headers=headers)

    if response.status_code != 200:
        print(("Login (when supplying token to get plan) failed (status: {0}). Exiting.").format(response.status_code))
        sys.exit(1)

    plan = json.loads(response.content)
    task_map = search_ids_names(None, {}, plan)

    # Job event stream
    url = '{0}/api/v1/builds/{1}/events'.format(concourse_hostname, build_number)
    headers = {
        'Authorization': 'Bearer {0}'.format(token),
        'Accept': 'text/event-stream'
    }

    response = requests.get(url, verify=False, headers=headers, stream=True)

    if response.status_code != 200:
        print(("Job failed but unable to fetch event stream (status: {0}). Exiting.").format(response.status_code))
        sys.exit(1)

    client = sseclient.SSEClient(response)

    logs = {}

    # This line identifies we are reading output stream from task id where teams notification runs. There is no way to get current task ID so 'EventReaderWaterMark' acts as a pointer so the script knows not to record its own logs (gets stuck in a loop when it does)
    resourceTaskId = None
    sys.stderr.write("EventReaderWaterMark: Retrieving event log from concourse\n")
    sys.stderr.flush()

    try:
        for event in client.events():
            if event.event == 'end':
                break

            edata = json.loads(event.data)
            if edata['event'] == "finish-task" and edata['data']['exit_status'] == 0:
                taskId = edata['data']['origin']['id']
                logs.pop(taskId, None)

            if edata['event'] == "log":
                taskId = edata['data']['origin']['id']
                logs[taskId] = logs.get(taskId, "") + edata['data']['payload']
                if edata['data']['payload'].startswith("EventReaderWaterMark:"):
                    resourceTaskId = taskId
                    break

    except requests.exceptions.Timeout as e:
      pass

    if resourceTaskId:
      logs.pop(resourceTaskId, None)

# messagecards for teams require \n\n for a new line
    output=("\n").join("\n--------------\n".join([task_map[k.split('/')[0]], v]) for k,v in list(logs.items()))
    output = output.replace("\n","\n\n")
    if len(output) > log_max_length:
        output = output[:log_max_length] + f'\n\n... truncating error log - message over {log_max_length}'

    print(json.dumps(output))

if __name__ == '__main__':
    main()
