#!/usr/bin/python

from __future__ import (absolute_import, division, print_function)
from email.policy import default

__metaclass__ = type

DOCUMENTATION = r'''
---
module: ansible_module_trivy

short_description: Trivy vulnerability output

# If this is part of a collection, you need to use semantic versioning,
# i.e. the version is of the form "2.5.0" and not "2.4".
version_added: "1.0.0"

description: This is a module to get the vulnerability output from a docker image

options:
    image:
        description: Image name to scan with trivy for vulnerabilities
        required: true
        type: str
# Specify this value according to your collection
# in format of namespace.collection.doc_fragment_name
extends_documentation_fragment:
    - my_namespace.my_collection.my_doc_fragment_name

author:
    - Dominik Hahn (@Devilluminati)
'''

EXAMPLES = r'''
- name: Run trivy normal
    ansible_module_trivy:
        type: 'image'
        image: 'microservice'
        dest: 'trivy_normal.log'

- name: Run trivy with severity
    ansible_module_trivy:
        type: 'image'
        image: 'microservice'
        severities: 
            - HIGH
        dest: 'trivy_severity.log'

- name: Run trivy with ignored unfixed
    ansible_module_trivy:
        type: 'image'
        image: 'microservice'
        unfixed: true
        dest: 'trivy_ignore_unfixed.log'

- name: Run trivy config
    ansible_module_trivy:
        type: 'config'
        path: './build'
        dest: 'trivy_config.log'
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.
message:
    description: The output message that the test module generates.
    type: str
    returned: always
    sample: 'Successfully writen to path'
'''

import subprocess
import os

from ansible.module_utils.basic import AnsibleModule

def scan_image(module):
    if module.params['severities']:
        output = subprocess.run(['trivy', 'image', '--severity', ','.join(module.params['severities']), module.params['image']], capture_output=True, text=True).stdout
    if module.params['unfixed']:
        output = subprocess.run(['trivy', 'image', '--ignore-unfixed', module.params['image']], capture_output=True, text=True).stdout
    else:    
        output = subprocess.run(['trivy', 'image', module.params['image']], capture_output=True, text=True).stdout
    write_to_file(module, output)

def scan_directory(module):
    output = subprocess.run(['trivy', 'config', module.params['path']], capture_output=True, text=True).stdout
    write_to_file(module, output)

def write_to_file(module, output):
    try:
        os.unlink(module.params['dest'])
    except:
        print('Error while deleting file')
    with open(module.params['dest'], 'a') as f:
        print(output, file=f)

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        type=dict(type='str', required=True),
        path=dict(type='str', required=False),
        image=dict(type='str', required=False),
        unfixed=dict(type='bool', required=False, default=False),
        severities=dict(type='list', required=False),
        dest=dict(type='str', required=True)
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        message=''
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    # during the execution of the module, if there is an exception or a
    # conditional state that effectively causes a failure, run
    # AnsibleModule.fail_json() to pass in the message and the result
    if module.params['type'] == 'image' and module.params['image'] == '':
        module.fail_json(msg='If you want to scan an image, you have to put in an image name.', **result)

    if module.params['type'] == 'dir' and module.params['path'] == '':
        module.fail_json(msg='If you want to scan a directory, you have to enter a path.', **result)

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    if module.params['type'] == 'image':
        scan_image(module)

    if module.params['type'] == 'dir':
        scan_directory(module)

    result['message'] = 'Successfully writen to ' + module.params['dest']
    result['changed'] = True
    
    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()