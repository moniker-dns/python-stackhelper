# Useful OpenStack Helper Commands

## Install

~~~
pip install stackhelper
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
~~~
