Concourse Teams Notification Resource
==================

Sends alerts to Teams.
This resource can now send log output of failing Concourse task(s) to Teams.

Resource Type Configuration
---------------------------

```yml
resource_types:
- name: teams-notification
  type: docker-image
  source:
    repository: fidelityinternational/concourse-teams-resource
    tag: latest
```

Source Configuration
--------------------

The following fields are required if you want to see erroring Concourse task output in the Teams notification:

- url: Teams webhook url
- atc_external_url: *Optional* The ATC external URL (if username and password is supplied but not the ATC URL, it will attempt to use the standard in-built ATC_EXTERNAL_URL instead)
- atc_username: *Optional* ATC username is required if atc_external_url is supplied.
- atc_password: *Optional* ATC password is required if atc_external_url is supplied.
- log_max_length: *Optional* Log max length can be configured here. Is necessary as Teams has a character limit on messages received.

Example resource config:

```yml
resources:
- name: teams-alert
  type: teams-notification
  source:
    url: ((teams_webhook))
    atc_external_url: ...
    atc_username: ...
    atc_password: ...
    log_max_length: ...
```

Behaviour
--------

### Sends alert to teams

Send alert to teams with the configured parameters.

#### Parameters

Required:

- `status`: 'failure' or 'success' for whether resource is called under on_failure or on_success.

Example
-------

```yml
on_failure: # or on_success:
        do:
        - put: teams-alert
          params:
            status: failure #or status: success
```

See our sample [test-pipeline.yml](test-pipeline.yml) for a working example.

Testing
-------

To test this resource, either:

1. Using test-pipeline, add resource, resource type, and on_failure/on_success examples to an existing pipeline, or

2. install a test Concourse with Docker.

Push the sample pipeline to it (remember to update the Teams resource configuration options first, as appropriate):

``` sh
fly login -t local -c http://localhost:8080 -u <local-username> -p <local-password>
fly -t local set-pipeline -p test -c test-pipeline.yml
```

Browse http://localhost:8080 and run the monitoring-test job. One of the tasks in that job is supposed to succeed, and one is supposed to fail. Note the Teams put: on the failing job. This should now trigger, so check Teams for an incoming alert.

Inside the alert message you should find pipeline, job_name, concourse_build_url and output fields which contain the logs from failed or succeeded jobs.
>>>>>>> 9ac5c11... Teams notification resource for concourse
