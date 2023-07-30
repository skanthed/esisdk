#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


def normalize_keys(config):
    new_config = {}
    for key, value in config.items():
        key = key.replace('-', '_')
        if isinstance(value, dict):
            new_config[key] = normalize_keys(value)
        elif isinstance(value, bool):
            new_config[key] = value
        elif isinstance(value, int) and key not in (
            'verbose_level',
            'api_timeout',
        ):
            new_config[key] = str(value)
        elif isinstance(value, float):
            new_config[key] = str(value)
        else:
            new_config[key] = value
    return
