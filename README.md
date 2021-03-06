# Useful OpenStack Helper Commands

## Install

~~~
pip install python-stackhelper
~~~

## Usage:

### Security Group Synchronization

~~~
$ stackhelper secgroup-sync --secgroup-json secgroups.example.json
Deleting group: testing
Creating group: chef
Creating group: haproxy
Creating group: apt
Create rule ALLOW tcp/80-80 FROM 'chef' in group 'apt'
Create rule ALLOW tcp/80-80 FROM 'haproxy' in group 'apt'
Create rule ALLOW tcp/4000-4000 FROM 'apt' in group 'chef'
Create rule ALLOW tcp/4000-4000 FROM 'haproxy' in group 'chef'
Create rule ALLOW tcp/443-443 FROM '0.0.0.0/0' in group 'haproxy'

$ nova secgroup-add-rule chef tcp 100 200 0.0.0.0/0
+-------------+-----------+---------+-----------+--------------+
| IP Protocol | From Port | To Port | IP Range  | Source Group |
+-------------+-----------+---------+-----------+--------------+
| tcp         | 100       | 200     | 0.0.0.0/0 |              |
+-------------+-----------+---------+-----------+--------------+

$ stackhelper secgroup-sync --secgroup-json secgroups.example.json
Delete rule ALLOW tcp/100-200 in group 'chef'
~~~

# Credential Management

No OS_ vars
~~~
$ env | grep OS_
$
~~~

Run stackhelper (inside backticks)
~~~
$ `stackhelper credentials hpcloud az1 exampleuser`
~~~

Check the OS_ env var's again:
~~~
$ env | grep OS_
OS_REGION_NAME='az-1.region-b.geo-1'
OS_TENANT_ID='...'
OS_PASSWORD='...'
OS_AUTH_URL='...'
OS_USERNAME='...'
OS_TENANT_NAME='...'
~~~
