import json, requests, sseclient, sys, urllib3

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

    # Login
    # OAuth2 token request
    url = '{0}/sky/issuer/token'.format(concourse_hostname)
    payload = {
      'grant_type': 'password',
      'username': concourse_username,
      'password': concourse_password,
      'scope': 'openid profile email federated:id groups'
    }

    response = requests.post(url, verify=False, data=payload, auth=('fly', 'Zmx5'))

    if response.status_code != 200:
        print(("Login failed (status: {0}). Exiting.").format(response.status_code))
        sys.exit(1)

    token = json.loads(response.content)['access_token']

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
        output = ""
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
    output=("\n").join("\n--------------\n".join([task_map[k], v]) for k,v in list(logs.items()))
    print(json.dumps(output.replace("\n","\n\n")))

if __name__ == '__main__':
    main()
