# -*- coding: utf-8 -*-
'''
Module for managing containers, configured through `Docker-Map <https://github.com/merll/docker-map>`_, along with
dependencies in Salt states.

This execution module provides the functionality of the ``container_map`` state module. The only function that is
not available as a state is :func:`script`, which runs a script or single-command in a container, specifically
created for this purpose.
'''
from __future__ import unicode_literals

from collections import defaultdict
import logging
import os
import shutil
import tempfile
import traceback
import sys
from itertools import groupby
from operator import itemgetter

from docker.errors import APIError, DockerException, NotFound

from dockermap.functional import expand_type_name, resolve_deep
from dockermap.api import (DockerClientWrapper, ClientConfiguration, ContainerMap, MappingDockerClient,
                           DockerFile, DockerContext, ActionRunnerException, PartialResultsError, DockerStatusError,
                           MapIntegrityError)
from dockermap.map.action import Action, ImageAction
from dockermap.map.config.utils import get_map_config_ids
from dockermap.map.input import ItemType
from dockermap.map.policy.utils import get_instance_volumes
from dockermap.map.runner import AbstractRunner, ActionOutput
from dockermap.map.state import StateFlags
from salt.exceptions import SaltInvocationError
from salt.ext import six
from salt.ext.six.moves import zip
from salt.utils import clean_kwargs


VIRTUAL_NAME = 'container_map'

SUMMARY_EXCEPTIONS = (KeyError, ValueError, APIError, DockerException, MapIntegrityError, DockerStatusError)
ANY_NETWORK_UPDATE = StateFlags.NETWORK_DISCONNECTED | StateFlags.NETWORK_LEFT | StateFlags.NETWORK_MISMATCH

get_action_output_cid_key = itemgetter(ActionOutput._fields.index('config_id'))
log = logging.getLogger(__name__)

try:
    from msgpack import ExtType
    use_ext_type = True
except ImportError:
    log.warning("Failed to import 'ExtType', probably due to an outdated msgpack library. Please install a more recent "
                "version in order to work with pillar and grain values in templates.")
    ExtType = None
    use_ext_type = False


def __virtual__():
    return VIRTUAL_NAME


def _get_resolver(code_pillar, code_grain):
    class ValueNotFound(object):
        pass

    get_pillar = __salt__['pillar.get']
    get_grain = __salt__['grains.get']

    def _resolve(ext_data):
        code = ext_data.code
        if code == code_pillar:
            value = get_pillar(ext_data.data, ValueNotFound)
            if value is ValueNotFound:
                raise KeyError("No pillar value '{0}' found.".format(ext_data.data))
            return value
        elif code == code_grain:
            value = get_grain(ext_data.data, ValueNotFound)
            if value is ValueNotFound:
                raise KeyError("No grain value '{0}' found.".format(ext_data.data))
            return value
        return ext_data

    return _resolve


def _get_setting(prefix, name, default=None):
    pg_name = '{0}:{1}'.format(prefix, name)
    value = __salt__['pillar.get'](pg_name, None)
    if value is not None:
        return value
    value = __salt__['grains.get'](pg_name, None)
    if value is not None:
        return value
    config_name = '{0}.{1}'.format(prefix, name)
    return __salt__['config.get'](config_name, default)


def _get_single_ip_addresses(ipv6):
    for if_name, if_addresses in six.iteritems(__salt__['grains.get']('ip_interfaces', {})):
        for addr in if_addresses:
            if ':' in addr:
                if ipv6:
                    yield if_name, addr
                    break
            elif not ipv6:
                yield if_name, addr
                break


def _exc_message(e):
    return ''.join(traceback.format_exception_only(type(e), e))


def _get_action_state(a):
    v = a.value
    av, __, ao = v.partition('_')
    if ao:
        v = '{0}_{1}'.format(ao, av)
    if v[-1:] == 'e':
        return '{0}d'.format(v)
    return '{0}ed'.format(v)


def _get_item_name(config_id):
    if config_id.instance_name:
        return '{0[0].value}:{0[1]}.{0[2]}.{0[3]}'.format(config_id)
    return '{0[0].value}:{0[1]}.{0[2]}'.format(config_id)


def _get_success_comment(changes):
    if not changes:
        return "There are no changes to apply."
    elif __opts__['test']:
        return "{0} operations would have been performed.".format(len(changes))
    return "{0} operations finished successfully.".format(len(changes))


def _get_failure_comment(changes, error_message, fail_item=None, action=None):
    if fail_item:
        item_str = ' on {0}'.format(_get_item_name(fail_item))
        if action:
            action_str = ' during action {0}'.format(action)
        else:
            action_str = ''
    else:
        item_str = ''
        action_str = ''
    if changes:
        return ("{0} operations were finished, but one error occurred{1}{2}: "
                "{3}").format(len(changes), item_str, action_str, error_message)
    return "An error occurred{0}{1}. No changes were made: {2}".format(item_str, action_str, error_message)


def _create_client(initial_maps):
    """
    :type initial_maps: dict[unicode, ContainerMap]
    :rtype: SaltDockerMap
    """
    class TestOutputRunner(AbstractRunner):
        def __init__(self, *args, **kwargs):
            super(TestOutputRunner, self).__init__(*args, **kwargs)
            self._test_states = {}

        def run_actions(self, actions):
            for action in actions:
                a_types = action.action_types
                if Action.CREATE in a_types:
                    if Action.REMOVE in action.action_types:
                        new_state = 'updated'
                    else:
                        new_state = 'present'
                elif Action.REMOVE in a_types:
                    new_state = 'absent'
                elif ImageAction.PULL:
                    new_state = 'updated'
                else:
                    new_state = _get_action_state(a_types[-1])
                self._test_states[_get_item_name(action.config_id)] = new_state

        @property
        def test_states(self):
            return self._test_states

    class SaltDockerClient(DockerClientWrapper):
        """
        Enhanced Docker client for SaltStack, which maintains something similar to a change log based on container actions.
        """
        def __init__(self, *args, **kwargs):
            super(SaltDockerClient, self).__init__(*args, **kwargs)
            self._log = []
            self._state_images = None

        def tag(self, image, repository, tag=None, **kwargs):
            if not __opts__['test']:
                res = super(SaltDockerClient, self).tag(image, repository, tag=tag, **kwargs)
                if res and image.startwith('sha') or ':' not in image:
                    full_image = '{0}:{1}'.format(repository, tag or 'latest')
                    self._state_images[image] = full_image
                return res
            return True

        def images(self, **kwargs):
            image_list = super(SaltDockerClient, self).images(**kwargs)
            if not ('name' in kwargs or 'filters' in kwargs):
                image_dict = dict()
            else:
                image_dict = self._state_images
            for i in image_list:
                tags = i.get('RepoTags')
                if tags:
                    image_id = i['Id']
                    image_dict.update({tag: image_id for tag in tags})
            self._state_images = image_dict
            return image_list

        def push_log(self, info, *args, **kwargs):
            super(SaltDockerClient, self).push_log(info, *args, **kwargs)
            self._log.append(info)

        def run_cmd(self, cmd):
            if not __opts__['test']:
                __salt__['cmd.run'](cmd)

        def flush_log(self):
            l = self._log
            self._log = []
            return l

        def get_state_images(self, refresh=False):
            if self._state_images is None or refresh is True:
                self.images()
            elif refresh:
                self.images(name=refresh)
            return self._state_images

    class SaltDockerClientConfig(ClientConfiguration):
        """
        Enhanced Docker client configuration object for SaltStack. Maps the interfaces directly to the 'ip_interfaces'
        generated from grains.
        """
        client_constructor = SaltDockerClient

        def __init__(self, *args, **kwargs):
            for name in ('timeout', 'version', 'stop_timeout', 'wait_timeout'):
                if name not in kwargs:
                    value = _get_setting('docker', name)
                    if value is not None:
                        kwargs[name] = value
            if 'base_url' not in kwargs:
                value = _get_setting('docker', 'url')
                if value is not None:
                    kwargs['base_url'] = value
                elif 'DOCKER_HOST' in os.environ:
                    kwargs['base_url'] = os.environ['DOCKER_HOST']
            if 'domainname' not in kwargs:
                kwargs['domainname'] = _get_setting('container_map', 'domainname')
            interfaces_ipv4 = dict(_get_single_ip_addresses(False))
            interfaces_ipv6 = dict(_get_single_ip_addresses(True))
            aliases = _get_setting('container_map', 'interface_aliases', {})
            for interfaces in (interfaces_ipv4, interfaces_ipv6):
                aliased_if = {alias: interfaces.get(if_name)
                              for alias, if_name in six.iteritems(aliases)}
                interfaces.update(aliased_if)
            kwargs['interfaces'] = interfaces_ipv4
            kwargs['interfaces_ipv6'] = interfaces_ipv6
            log.debug("Creating client config: %s", kwargs)
            kwargs['auth_configs'] = __salt__['pillar.get']('docker-registries', None)
            super(SaltDockerClientConfig, self).__init__(*args, **kwargs)

    class SaltDockerMap(MappingDockerClient):
        """
        Adapted :class:`~dockermap.map.client.MappingDockerClient`.
        """
        configuration_class = SaltDockerClientConfig

        def __init__(self, *args, **kwargs):
            super(SaltDockerMap, self).__init__(*args, **kwargs)
            self._default_client_name = default_name = self.policy_class.default_client_name
            self._default_config = self.clients[default_name]
            base_image = _get_setting('container_map', 'base_image')
            if base_image:
                self.policy_class.base_image = base_image
            core_image = _get_setting('container_map', 'core_image')
            if core_image:
                self.policy_class.core_image = core_image
            self._test_states = None

        @property
        def default_client_name(self):
            """
            Alias name of the default client.

            :return: unicode
            """
            return self._default_client_name

        @property
        def default_client(self):
            """
            :return: Default client.
            :rtype: SaltDockerClient
            """
            return self._default_config.get_client()

        def get_runner(self, policy, kwargs):
            if __opts__['test']:
                runner = TestOutputRunner(policy, kwargs)
                self._test_states = runner.test_states
                return runner
            self._test_states = None
            return super(SaltDockerMap, self).get_runner(policy, kwargs)

        def run_actions(self, action_name, *args, **kwargs):
            is_test = __opts__['test']
            states_before = list(self.get_states(action_name, *args, **kwargs))
            changes = {}
            results = {
                'changes': changes,
            }
            try:
                action_output = super(SaltDockerMap, self).run_actions(action_name, *args, **kwargs)
            except ActionRunnerException as e:
                exc = e
                action_output = e.results
            else:
                exc = None

            output = {
                _get_item_name(config_id): [
                    [ao.action_type.value, ao.result]
                    for ao in config_output
                ]
                for config_id, config_output in groupby(action_output, get_action_output_cid_key)
            }
            if output:
                results['output'] = output

            if action_name == 'signal':
                for old_state in states_before:
                    item_name = _get_item_name(old_state.config_id)
                    changes[item_name] = {'old': old_state.base_state.value,
                                          'new': 'signaled'}
            else:
                if is_test:
                    new_states = self._test_states
                else:
                    new_states = {_get_item_name(state.config_id): state
                                  for state in self.get_states(action_name, *args, **kwargs)}
                for old_state in states_before:
                    item_name = _get_item_name(old_state.config_id)
                    new_state = new_states[item_name]
                    if new_state.base_state == old_state.base_state:
                        new_detail = new_state.extra_data
                        old_detail = old_state.extra_data
                        if new_detail.get('id') != old_detail.get('id'):
                            changed_state = 'updated'
                        elif new_detail.get('pid') != old_detail.get('pid'):
                            changed_state = 'restarted'
                        elif old_state.state_flags & ANY_NETWORK_UPDATE:
                            changed_state = 'network-updated'
                        elif old_state.state_flags & StateFlags.EXEC_COMMANDS:
                            changed_state = 'exec-command-run'
                        else:
                            changed_state = None
                    else:
                        changed_state = new_state.base_state.value
                    if changed_state:
                        changes[item_name] = {'old': old_state.base_state.value,
                                              'new': changed_state}
            if is_test:
                if changes:
                    results['result'] = True
                else:
                    results['result'] = None
                results['comment'] = _get_success_comment(changes)
            elif exc is None:
                results['result'] = True
                results['comment'] = _get_success_comment(changes)
            else:
                error_message = exc.source_message
                results['result'] = False
                results['comment'] = _get_failure_comment(changes, error_message, exc.config_id)
            return results

    log.debug("Creating SaltDockerMap instance.")
    default_config = SaltDockerClientConfig()
    client = SaltDockerMap(initial_maps, default_config)
    __context__['container_map.client'] = client
    return client


def _status(client, item_id=None, exception=None, output=None):
    if not exception:
        changes = client.flush_changes()
        if not changes:
            comment = "There are no changes to apply."
        elif __opts__['test']:
            comment = "{0} operations would have been performed.".format(len(changes))
        else:
            comment = "{0} operations finished successfully.".format(len(changes))
        result_dict = {
            'result': True,
            'comment': comment,
            'changes': changes,
        }
        if output:
            result_dict['out'] = output
        return result_dict

    fail = client.last_action or {}
    changes = client.flush_changes()
    error_message = _exc_message(exception)
    if changes:
        if fail:
            comment = ("{0} operations were finished, but one error occurred when changing {1[item_type]} "
                       "{1[item_id]} from {1[old]} to {1[new]}: {2}").format(len(changes), fail, error_message)
        else:
            comment = ("{0} operations were finished, but one error occurred in a preparation of further actions: "
                       "{0}.".format(len(changes)), error_message)
    else:
        if fail:
            comment = ("An error occurred when changing {0[item_type]} {0[item_id]} from {0[old]} to {0[new]}. "
                       "No changes were made: {1}").format(fail, error_message)
        else:
            comment = ("An error occurred during preparation. No changes were made: "
                       "{0}").format(error_message)
    return dict(result=False, item_id=item_id or fail.get('item_id'), changes=changes, comment=comment,
                out=output or traceback.format_exc())


def _get_build_files(files, saltenv):
    if not files:
        return None
    if isinstance(files, dict):
        file_iter = six.iteritems(files)
    elif isinstance(files, list):
        file_iter = [next(six.iteritems(item)) if isinstance(item, dict) else item
                     for item in files]
    else:
        raise SaltInvocationError("Invalid parameter for source files; must be a dictionary or list.")
    sources, targets = zip(*file_iter)
    cached_sources = __salt__['cp.cache_files'](list(sources), saltenv=saltenv)
    return list(zip(cached_sources, targets))


def get_client():
    '''
    Creates and returns the client. The client is only instantiated once and not re-created for multiple requests.
    '''
    client = __context__.get('container_map.client')
    if client:
        return client

    config_get = __salt__['config.get']
    if use_ext_type:
        log.debug("Configuring ExtType.")
        ext_resolver = _get_resolver(config_get('lazy_yaml.ext_code_pillar', 10),
                                     config_get('lazy_yaml.ext_code_grain', 11))
        resolve_dict = {expand_type_name(ExtType): ext_resolver}
    else:
        resolve_dict = {}
    log.debug("Loading container maps.")
    pillar_name = config_get('container_map.pillar_name', 'container_maps')
    map_dicts = __salt__['pillar.get'](pillar_name, {})
    all_maps = {}
    attached_parent_name = _get_setting('container_map', 'use_attached_parent_name', False)
    skip_checks = _get_setting('container_map', 'skip_checks', False)
    raise_map_errors = _get_setting('container_map', 'raise_map_errors', True)
    if map_dicts:
        log.info("Initializing container maps: %s", ', '.join(map_dicts.keys()))
        merge_maps = defaultdict(list)
        copy_maps = []
        for map_name, map_content in six.iteritems(map_dicts):
            try:
                resolved_content = resolve_deep(map_content, types=resolve_dict)
            except KeyError as e:
                exc_info = sys.exc_info()
                log.error("Skipping map %s due to error: %s", map_name, e.args[0])
                if raise_map_errors:
                    six.reraise(*exc_info)
            else:
                merge_into = resolved_content.pop('merge_into', None)
                copy = resolved_content.pop('extend_copy', None)
                if merge_into:
                    merge_maps[merge_into].append(resolved_content)
                elif copy:
                    copy_maps.append((map_name, copy, resolved_content))
                else:
                    check_integrity = not resolved_content.pop('skip_check', skip_checks)
                    a_p_name = resolved_content.pop('use_attached_parent_name', attached_parent_name)
                    try:
                        c_map = ContainerMap(map_name, resolved_content, check_integrity=check_integrity,
                                             use_attached_parent_name=a_p_name)
                        all_maps[map_name] = c_map
                    except MapIntegrityError as e:
                        exc_info = sys.exc_info()
                        log.error("Skipping map %s because of integrity error: %s", map_name, e.message)
                        if raise_map_errors:
                            six.reraise(*exc_info)
        for map_name, merge_contents in six.iteritems(merge_maps):
            merge_into_map = all_maps.get(map_name)
            if merge_into_map:
                for merge_content in merge_contents:
                    merge_into_map.merge(merge_content, lists_only=merge_content.pop('merge_lists_only', False))
            else:
                log.error("Map %s is not available for merging into: %s", merge_into_map, map_name)
        for map_name, extend_name, merge_content in copy_maps:
            copy_from_map = all_maps.get(extend_name)
            if copy_from_map:
                check_integrity = not merge_content.pop('skip_check', skip_checks)
                a_p_name = merge_content.pop('use_attached_parent_name', attached_parent_name)
                new_map = ContainerMap(map_name, copy_from_map, check_integrity=False,
                                       use_attached_parent_name=a_p_name)
                new_map.merge(merge_content, lists_only=merge_content.pop('merge_lists_only', False))
                if check_integrity:
                    try:
                        new_map.check_integrity()
                    except MapIntegrityError as e:
                        exc_info = sys.exc_info()
                        log.error("Skipping map %s because of integrity error: %s", map_name, e.message)
                        if raise_map_errors:
                            six.reraise(*exc_info)
                all_maps[map_name] = new_map
            else:
                log.error("Map %s is not available for extension: %s", extend_name, map_name)

    return _create_client(all_maps)


def setup(name, containers=None, volumes=None, host=None, host_root=None, repository=None, default_domain=None,
          check_integrity=True, ignore_existing=False):
    '''
    Sets up a container map.

    name
        Name of the container map.
    containers
        Container configurations to load.
    volumes
        Volume aliases, each with the path of their container mount point.
    host
        Volume aliases, each with the path of their host mount point.
    host_root
        Host root path to prefix all host paths with, unless they are absolute paths.
    repository
        Default repository name to prefix image names with, unless they are specified with a different prefix.
    default_domain
        Default domain to set for new containers.
    check_integrity : True
        Whether to check the map for missing containers and volume aliases. Set to ``False`` if the map is to be
        complemented with ``merged``.
    ignore_existing : False
        In case a map with the given name exists, this state will fail. Setting this to ``True`` overwrites existing
        maps instead.
    '''
    m = get_client()
    if name not in m.maps:
        try:
            map_config = ContainerMap(name, containers=containers, volumes=volumes, host=host, host_root=host_root,
                                      repository=repository, default_domain=default_domain,
                                      check_integrity=check_integrity)
            m.maps[name] = map_config
            m.refresh_names()
        except SUMMARY_EXCEPTIONS as e:
            return dict(result=False, item_id=name, changes={}, comment="Failed to load map '{0}': {1}.".format(
                name, _exc_message(e)), out=traceback.format_exc())
    elif not ignore_existing:
        return dict(result=False, item_id=name, changes={},
                    comment="A map with name '{0}' is already loaded.".format(name))
    return dict(result=True, item_id=name, changes={}, comment="Map '{0}' loaded.".format(name))


def merge(name, containers=None, volumes=None, host=None, host_root=None, repository=None, default_domain=None,
          lists_only=False):
    '''
    Merges the given map into an existing container map. This means that list-like properties are extended and
    dictionaries on the target map are updated.

    name
        State name - has no effect.
    target_map
        Name of the container map to merge the following contents into.
    containers
        Container configurations to load.
    volumes
        Volume aliases, each with the path of their container mount point.
    host
        Volume aliases, each with the path of their host mount point.
    host_root
        Host root path to prefix all host paths with, unless they are absolute paths.
    repository
        Default repository name to prefix image names with, unless they are specified with a different prefix.
    default_domain
        Default domain to set for new containers.
    lists_only : False
        By default single-value properties (e.g. host_root) are overwritten on the target map. If set to ``True``,
        these properties are ignored if they are already set on the target.
    '''
    m = get_client()
    try:
        map_dict = dict(
            containers=containers,
            volumes=volumes,
            host=host,
            host_root=host_root,
            repository=repository,
            default_domain=default_domain
        )
        existing_config = m.maps.get(name)
        if existing_config:
            existing_config.merge(map_dict, lists_only=lists_only)
        else:
            m.maps[name] = ContainerMap(name, initial=map_dict, check_integrity=False)
        m.refresh_names()
    except SUMMARY_EXCEPTIONS as e:
        return dict(result=False, item_id=name, changes={}, comment="Failed to merge map '{0}': {1}.".format(
            name, _exc_message(e)), out=traceback.format_exc())
    return dict(result=True, item_id=name, changes={}, comment="Map '{0}' loaded.".format(name))


def create(container, instances=None, map_name=None, **kwargs):
    '''
    Creates a container, along with its dependencies. Existing containers are not re-created.

    container
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    kwargs
        Extra keyword arguments for the container creation.
    '''
    return get_client().create(container, instances=instances, map_name=map_name, **clean_kwargs(**kwargs))


def start(container, instances=None, map_name=None, **kwargs):
    '''
    Starts a container, along with its dependencies. Fails on non-existing containers, but not on containers that are
    already started.

    container
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    kwargs
        Extra keyword arguments for the container start.
    '''
    return get_client().start(container, instances=instances, map_name=map_name, **clean_kwargs(**kwargs))


def stop(container, instances=None, map_name=None, **kwargs):
    '''
    Stops a container, along with its dependent containers. Ignores non-existing or non-running containers.

    container
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    kwargs
        Extra keyword arguments for the container stop.
    '''
    return get_client().stop(container, instances=instances, map_name=map_name, **clean_kwargs(**kwargs))


def remove(container, instances=None, map_name=None, **kwargs):
    '''
    Removes a container, along with its dependent containers. Ignores non-existing containers, but fails on running
    containers.

    container
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    kwargs
        Extra keyword arguments for the container removal.
    '''
    return get_client().remove(container, instances=instances, map_name=map_name, **clean_kwargs(**kwargs))


def restart(container, instances=None, map_name=None, **kwargs):
    '''
    Restarts a container.

    container
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    kwargs
        Extra keyword arguments for the container restart.
    '''
    return get_client().restart(container, instances=instances, map_name=map_name, **clean_kwargs(**kwargs))


def startup(container, instances=None, map_name=None, **kwargs):
    '''
    Creates and starts a container as needed, along with its dependencies. Ignores running containers.

    container
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    kwargs
        Extra keyword arguments for the container startup.
    '''
    return get_client().startup(container, instances=instances, map_name=map_name, **clean_kwargs(**kwargs))


def shutdown(container, instances=None, map_name=None, **kwargs):
    '''
    Stops and removes a container as needed, along with its dependent containers. Ignores non-existing containers.

    container
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    kwargs
        Extra keyword arguments for the container shutdown.
    '''
    return get_client().shutdown(container, instances=instances, map_name=map_name, **clean_kwargs(**kwargs))


def update(container, instances=None, map_name=None, reload_signal=None, **kwargs):
    '''
    Ensures that a container is up-to-date, i.e.
    * the image id corresponds with the image tag from the configuration
    * the existing container still has access to all dependent volumes
    * linked containers are available
    * command, entrypoint, or environment have not been changed.

    Non-existing containers are created and started. Outdated containers are removed and re-created and restarted along
    the dependency path.

    container
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    reload_signal
        Optional signal to send to the main process in case the container has not just been created.
    kwargs
        Extra keyword arguments for the container update.
    '''
    m = get_client()
    policy = m.get_policy()
    config_ids = get_map_config_ids(container, policy.container_maps, map_name, instances)
    res = m.update(config_ids, **clean_kwargs(**kwargs))
    is_test = __opts__['test']
    if reload_signal:
        changes = res['changes']
        res_comment = '{0}\n'.format(res['comment']) if changes else ''
        updated = {item for item, status in six.iteritems(changes)
                   if status['new'] == 'updated'}
        errors = {}
        signaled = {}
        c = m.default_client
        for config_id in config_ids:
            item_name = _get_item_name(config_id)
            if item_name in updated:
                continue
            if is_test:
                signaled[item_name] = {'old': 'running', 'new': 'signaled'}
                continue
            ci_name = policy.cname(config_id.map_name, config_id.config_name, config_id.instance_name)
            try:
                c.kill(ci_name, signal=reload_signal)
            except SUMMARY_EXCEPTIONS as e:
                errors[item_name] = _exc_message(e)
            else:
                signaled[item_name] = {'old': 'running', 'new': 'signaled'}
        changes.update(signaled)
        if errors:
            if signaled:
                comment = "{0}Failed to send signal {1} to some containers.".format(res_comment, reload_signal)
            else:
                comment = "{0}Failed to send signal {1} to all containers.".format(res_comment, reload_signal)
            res.update(result=False, comment=comment, out=errors)
        else:
            res['comment'] = "{0}Signal {1} sent to selected containers.".format(res_comment, reload_signal)
    return res


def kill(container, instances=None, map_name=None, signal=None, **kwargs):
    return get_client().signal(container, instances=instances, map_name=map_name, signal=signal, **clean_kwargs(**kwargs))


def cleanup_containers(include_initial=False, exclude=None):
    '''
    Removes all containers from the host which are not running, not attached volume containers, and not marked as
    persistent. Note this also applies to containers that are not on any map.
    '''
    m = get_client()
    excluded_names = set(exclude or ())
    excluded_names.update(m.list_persistent_containers())
    log.debug("Removing stopped containers (Exceptions: %s).", ', '.join(excluded_names))
    c = m.default_client
    is_test = __opts__['test']
    try:
        removed_containers = c.cleanup_containers(include_initial=include_initial, exclude=excluded_names,
                                                  list_only=is_test)
    except PartialResultsError as e:
        removed_containers = e.results
        error_message = e.source_message
        if is_test:
            result = None
        else:
            result = False
    else:
        result = True
        error_message = None
    changes = {'container:{0}'.format(image): {'old': 'running', 'new': 'absent'}
               for image in removed_containers}
    if result:
        comment = _get_success_comment(changes)
    else:
        comment = _get_failure_comment(changes, error_message)
    return {'result': result,
            'changes': changes,
            'comment': comment}


def cleanup_images(**kwargs):
    '''
    Removes all images from the host which are not in use by any container and have no tag. Optionally can also remove
    images with a repository tag that is not the ``latest`` or any other listed tag.

    remove_old : False
        Remove images that have a tag, but not ``latest``. Does not affect additional (e.g. version) tags of ``latest``
        images.
    keep_tags
        Keep only images that have any of the specified tags.
    '''
    c = get_client().default_client
    is_test = __opts__['test']
    kwargs.setdefault('list_only', is_test)
    try:
        removed_images = c.cleanup_images(**clean_kwargs(**kwargs))
    except PartialResultsError as e:
        removed_images = e.results
        error_message = e.source_message
        if is_test:
            result = None
        else:
            result = False
    else:
        result = True
        error_message = None
    changes = {'image:{0}'.format(image): {'old': 'present', 'new': 'absent'}
               for image in removed_images}
    if result:
        comment = _get_success_comment(changes)
    else:
        comment = _get_failure_comment(changes, error_message)
    return {'result': result,
            'changes': changes,
            'comment': comment}


def remove_all_containers(stop_timeout=None, shutdown_maps='__all__', shutdown_first=None):
    '''
    Removes all containers from the host.

    stop_timeout
        Timeout to stop containers before they are removed. Only applies to containers that do not have this set
        in the configuration, unless ``shutdown_maps`` is set to ``None`` and ``shutdown_first`` is not set.
    shutdown_maps
        List of maps to go over all container configurations and shut down properly prior to simply stopping and
        removing everything that is left on the host. Default is ``__all__``. Set to ``None`` for deactivating this
        behavior.
    shutdown_first
        Optional container configurations to shut down first, even before ``shutdown_maps``. Note that if this is set,
        and ``shutdown_maps`` is ``None``, a configuration without map specification will be looked up on all maps.
    '''
    stop_timeout = stop_timeout or _get_setting('docker', 'stop_timeout', 10)
    m = get_client()
    if shutdown_first:
        res = m.shutdown(shutdown_first, map_name=shutdown_maps or '__all__')
        if not res['result']:
            return res
    else:
        res = {}
    if shutdown_maps:
        res.update(m.shutdown('__all__', map_name=shutdown_maps))
        if not res['result']:
            return res
    c = m.default_client
    is_test = __opts__['test']
    try:
        stopped_containers, removed_containers = c.remove_all_containers(stop_timeout=stop_timeout, list_only=is_test)
    except PartialResultsError as e:
        stopped_containers, removed_containers = e.results
        error_message = e.source_message
        if is_test:
            result = None
        else:
            result = False
    else:
        result = True
        error_message = None
    changes = res['changes']
    changes.update({'container:{0}'.format(c): {'old': 'running', 'new': 'stopped'}
                    for c in stopped_containers})
    changes.update({'container:{0}'.format(c): {'old': 'running', 'new': 'absent'}
                    for c in removed_containers})
    if result:
        res['comment'] = _get_success_comment(changes)
    else:
        res['comment'] = _get_failure_comment(changes, error_message)
    return res


def call(action_name, container, instances=None, map_name=None, **kwargs):
    '''
    Call a container action.

    action_name
        Name of the action method, e.g. ``startup``.
    container
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    kwargs
        Extra keyword arguments for the container action.
    '''
    return get_client().call(action_name, container, instances=instances, map_name=map_name, **clean_kwargs(**kwargs))


def script(container, instance=None, map_name=None, wait_timeout=10, autoremove_before=False, autoremove_after=True,
           source=None, saltenv='base', template=None, contents=None, content_pillar=None, path=None, file_mode=None,
           dir_mode=None, user=None, group=None, entrypoint=None, command_format=None,
           container_script_dir='/tmp/script_run', allow_multiple=False, timestamps=None, tail='all', **kwargs):
    '''
    Runs a script inside a configured container. The container is specifically created for this purpose (in difference
    to the ``dockerio`` implementation, which executes in a running container). After the script is done, newly
    created containers are destroyed.

    container
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    wait_timeout : 10
        How many seconds to wait until the script is done running.
    autoremove_before : False
        If the configured container exists, the default behavior is to raise an exception. Set this to ``False`` to
        have the container removed.
    autoremove_after : True
        By default any container created in this process will be removed (except for attached and persistent ones).
        Setting this to ``False`` leaves them in place.
    source
        Script source file (e.g. ``salt://...`` for a script file loaded from the master).
    saltenv : 'base'
        Salt environment to use for loading source files.
    template
        Template engine to use for the source file.
    contents
        The script can be passed in here directly as a multiline string or list. Ignored if ``source`` is set.
    content_pillar
        Pillar to load the script contents from. Ignored if ``contents`` or ``source`` is set.
    path
        Path to use on the host to run the script in. Can also be used for writing back results. If not set, will
        create a temporary directory and remove it after the script has finished.
    file_mode
        File permissions to set on ``path`` before running.
    dir_mode
        Dir permissions to set on ``path`` before running.
    user
        User to set as owner to ``path`` before running.
    group
        Group to set as owner to ``path`` before running.
    entrypoint
        Entrypoint of the container. Overrides the entrypoint set in the configuration or the image.
    command_format
        Command to run in the container. Overrides the command set in the configuration or the image. Can include
        a variable ``{script_path}`` for substituting host-paths with container mount points.
    container_script_dir : '/tmp/script_run'
        Directory to use as mount point inside the container.
    allow_multiple : False
        By default only one container is allowed to run a script. This condition is enforced by checking the container
        names selected by the input (e.g. if there are mutiple instances). This check can be deactivated by setting
        this to ``True``. Note that in this case the aforementioned ``user`` has to be specified as it may be ambiguous
        otherwise.
    timestamps
        Include time stamps with `stdout` output. Passed to `docker-py`.
    tail : 'all'
        Only include a certain amount of lines from `stdout`. Passed to `docker-py`.
    '''
    if path:
        script_dir = path
        temporary_path = False
    else:
        script_dir = tempfile.mkdtemp()
        temporary_path = True
    script_path = None
    try:
        if source:
            f = tempfile.NamedTemporaryFile(dir=path, delete=False)
            script_path = f.name
            f.close()
            log.debug("Copying script to temporary file %s.", script_path)
            if template:
                __salt__['cp.get_template'](source, script_path, template=template, saltenv=saltenv)
            else:
                cached_name = __salt__['cp.cache_file'](source, saltenv)
                shutil.copyfile(cached_name, script_path)
        else:
            if content_pillar and not contents:
                contents = __salt__['pillar.get'](content_pillar)

            if contents:
                if isinstance(contents, list):
                    content_str = '\n'.join(contents)
                elif isinstance(contents, six.string_types):
                    content_str = contents
                else:
                    raise SaltInvocationError("Content must be either a string or a list of strings")
                with tempfile.NamedTemporaryFile(dir=script_dir, delete=False) as script_file:
                    script_path = script_file.name
                    log.debug("Writing script to temporary file %s.", script_path)
                    script_file.write(content_str)
                    if content_str[-1] != '\n':
                        script_file.write('\n')

        m = get_client()
        policy = m.get_policy()
        config_ids = get_map_config_ids(container, policy.container_maps, map_name, instance)
        config_count = len(config_ids)
        if config_count > 1 and not allow_multiple:
            raise SaltInvocationError("More than one ({0}) container would be run. Please narrow the selection or run "
                                      "with kwarg 'allow_multiple=True'.".format(config_count))

        if script_dir and config_count == 1:
            ch_user = user or m.maps[config_ids[0].map_name].containers[config_ids[0].config_name].user
            log.debug("Changing user of %s to %s.", script_dir, ch_user)
            __salt__['file.check_perms'](script_dir, {}, ch_user, group, dir_mode)
            if script_path:
                log.debug("Changing user of %s to %s.", script_path, ch_user)
                __salt__['file.check_perms'](script_path, {}, ch_user, group, file_mode)
        log.debug("Running script in container(s) %s.\nHost path: %s\nEntrypoint: %s\nCommand template: %s",
                  config_ids, script_path or script_dir, entrypoint, command_format)
        return m.run_script(config_ids,
                            script_path=script_path or script_dir,
                            entrypoint=entrypoint, command_format=command_format, wait_timeout=wait_timeout,
                            container_script_dir=container_script_dir, timestamps=timestamps, tail=tail,
                            remove_existing_before=autoremove_before, remove_created_after=autoremove_after,
                            **clean_kwargs(**kwargs))
    finally:
        if temporary_path:
            log.debug("Cleaning up temporary script dir %s.", script_dir)
            shutil.rmtree(script_dir, ignore_errors=True)
        elif script_path:
            try:
                log.debug("Cleaning up temporary script file %s.", script_path)
                os.unlink(script_path)
            except OSError:
                pass


def pull_images(container=None, map_name=None, utility_images=True, insecure_registry=False, **kwargs):
    '''
    Updates images on a map to their latest version or the specified tag. If neither container or map name are specified
    all images on all maps are being pulled.

    container
        Optional container configuration names.
    map_name
        Container map name.
    utility_images : True
        Unless set to ``False``, also updates utility images such as ``busybox`` and ``tianon/true``.
    insecure_registry : False
        Allow `insecure` registries for retrieving images.
    '''
    if not container:
        if not map_name:
            map_name = '__all__'
        container = '__all__'
    m = get_client()
    c = m.default_client
    policy = m.get_policy()
    res = m.pull_images(container, map_name=map_name, insecure_registry=insecure_registry, **clean_kwargs(**kwargs))
    output = res.get('output', {})
    # Removing output that has no additional info to changes.
    remove_output = {k for k, v in six.iteritems(output) if v[1] is True}
    for r in remove_output:
        del output[r]
    if utility_images:
        state_images = c.get_state_images()
        changes = res['changes']
        item_name = None
        try:
            for image_name in [policy.base_image, policy.core_image]:
                name, __, tag = image_name.rpartition(':')
                if name:
                    image_tag = image_name
                else:
                    name = tag
                    tag = 'latest'
                    image_tag = '{0}:latest'.format(name)
                item_name = 'image:{0}'.format(image_tag)
                prev_image_id = state_images.get(image_tag)
                c.pull(name, tag=tag, insecure_registry=insecure_registry)
                new_image_id = c.get_state_images(refresh=name)[image_tag]
                if prev_image_id != new_image_id:
                    changes[item_name] = {
                        'old': 'present' if prev_image_id else 'absent',
                        'new': 'updated',
                    }
        except SUMMARY_EXCEPTIONS as e:
            res['result'] = False
            res['comment'] = _get_failure_comment(changes, _exc_message(e), item_name)
        else:
            res['comment'] = _get_success_comment(changes)
    return res


def get_volumes(container=None, map_name=None, instances=None):
    '''
    Extracts volume information for one or multiple containers.

    container
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    '''
    m = get_client()
    policy = m.get_policy()
    config_ids = get_map_config_ids(container, policy.container_maps, map_name, instances)
    client = m.default_client
    all_volumes = {}
    for config_id in config_ids:
        if config_id.config_type != ItemType.CONTAINER:
            continue
        item_name = _get_item_name(config_id)
        c_name = policy.cname(config_id.map_name, config_id.config_name, config_id.instance_name)
        try:
            c_info = client.inspect_container(c_name)
        except NotFound:
            all_volumes[item_name] = "Container does not exist."
        else:
            all_volumes[item_name] = get_instance_volumes(c_info, True)
    return all_volumes


def refresh_client():
    '''
    Drops the cached client instance, and forces a re-instantiation on the next request.
    '''
    client = __context__.get('container_map.client')
    if not client:
        return False  # Delay until first necessary initialization.
    _create_client(client.maps)
    return True


def login(registry, username=None, password=None, email=None, reauth=False, **kwargs):
    '''
    Logs in to a registry. All parameters are optional, and in case they are no provided information
    will be read from the ``docker-registries`` pillar, if available.

    name
        Registry name.
    username
        Login user name.
    password
        Login password.
    email
        Login email (optional in most cases).
    reauth : False
        Force re-authentication, even if authentication data has been cached for this registry.
    kwargs
        Additional keyword arguments for the login.
    '''
    client = get_client().default_client
    try:
        result = client.login(username, password, email, registry=registry, reauth=reauth,
                              **clean_kwargs(**kwargs))
    except SUMMARY_EXCEPTIONS as e:
        return dict(result=False, item_id=registry, changes={}, comment=_exc_message(e))
    return dict(result=result, item_id=registry, changes={}, comment="Client logged in.")


def image_tag_exists(repo_tag):
    '''
    Returns whether an image with a given repository is present (optionally including a tag, otherwise ``latest`` is
    assumed).

    repo_tag
        Repository and optionally tag.
    '''
    images = get_client().default_client.get_state_images()
    repo_tag = '{0}:latest'.format(repo_tag) if ':' not in repo_tag else repo_tag
    return repo_tag in images


def build(tag, show_log=True, source=None, saltenv='base', template=None, context=None, contents=None,
          content_pillar=None, baseimage=None, maintainer=None, add_files=None, insert_files='before',
          dockerfile=None, **kwargs):
    '''
    tag
        Image tag to apply.
    show_log : True
        Return the build output.
    source
        Dockerfile source (e.g. ``salt://...`` for a file loaded from the master).
    saltenv : 'base'
        Salt environment to use for loading source files.
    template
        Template engine to use for the source file.
    context:
        Additional template context.
    contents
        The script can be passed in here directly as a multiline string or list. Ignored if ``source`` is set.
    content_pillar
        Pillar to load the script contents from. Ignored if ``contents`` or ``source`` is set.
    baseimage
        Image to base the build on. Ignored if ``source`` is used. Can also be included directly
        using the ``FROM`` Dockerfile command.
    maintainer
        Maintainer to state in the image. Ignored if ``source`` is used. Can also be included
        using the ``MAINTAINER`` Dockerfile command.
    add_files
        Files to add to the Docker context, formatted as a list of lists with two elements each. The
        first element is the source file, the second the target path in the docker image.
        ADD commands will be inserted according to ``insert_files``.
    insert_files : 'before'
        If ``add_files`` is set and ``contents`` is used, insert matching ADD commands:
        * 'before': before the contents. Can only be used if ``baseimage`` is
          defined here instead of being included in ``contents``.
        * 'after': after the contents
        * None: not at all. It is up to you to make sure the files get from the context into the
          template.

        This can also be used with ``source`` and ``template``. In that case place the name of
        the variable here to set inside the rendering context.
    dockerfile
        Dockerfile object. Only useful for other modules. Ignored if any of the aforementioned
        ``source``, ``contents``, or ``content_pillar`` is set. Ignores ``baseimage``,
        ``maintainer``, and ``add_files``.
    kwargs
        Additional keyword arguments for building the Docker image.
    '''
    if (content_pillar or contents) and add_files and not baseimage:
        raise SaltInvocationError("If the Dockerfile is generated by the state and files are to be "
                                  "added, 'baseimage' must be set instead of including it in the "
                                  "contents.")

    if add_files or template:
        file_list = _get_build_files(add_files, saltenv)
        file_inserts = '\n'.join(['ADD ["{0}", "{0}"]'.format(cached_target[1])
                                 for cached_target in file_list])
        tmp_path = tempfile.mkdtemp()
    else:
        file_list = None
        file_inserts = ''
        tmp_path = None

    try:
        if source:
            if template:
                build_context = DockerContext()
                template_kwargs = {
                    'template': template,
                    'saltenv': saltenv,
                }
                if file_list:
                    template_kwargs['context'] = template_context = {
                        insert_files: file_inserts
                    }
                    for cached_src, tgt in file_list:
                        build_context.add(cached_src, arcname=tgt)
                    if context:
                        template_context.update(context)
                else:
                    template_kwargs['context'] = context
                f = tempfile.NamedTemporaryFile(dir=tmp_path, delete=False)
                df_path = f.name
                f.close()
                log.debug("Copying Dockerfile to temporary file %s.", df_path)
                __salt__['cp.get_template'](source, df_path, **template_kwargs)
                build_context.add_dockerfile(df_path)
                build_context.finalize()
            else:
                cached_name = __salt__['cp.cache_file'](source, saltenv)
                log.debug("Using cached source file %s as Dockerfile.", cached_name)
                build_context = DockerContext(cached_name, finalize=True)

        elif content_pillar or contents:
            if content_pillar and not contents:
                contents = __salt__['pillar.get'](content_pillar)

            if not contents:
                raise SaltInvocationError("No content provided to create a Dockerfile.")

            if isinstance(contents, list):
                content_str = '\n'.join(contents)
            elif isinstance(contents, six.string_types):
                content_str = contents
            else:
                raise SaltInvocationError("Content must be either a string or a list of strings")

            if file_list:
                if insert_files == 'before':
                    content_join = [file_inserts, content_str]
                elif insert_files == 'after':
                    content_join = [content_str, file_inserts]
                elif not insert_files:
                    content_join = [content_str]
                else:
                    raise SaltInvocationError("Invalid setting '{0}' for 'insert_files' with "
                                              "contents.".format(insert_files))
                df_kwargs = {
                    'initial': '\n'.join(content_join)
                }
            else:
                df_kwargs = {
                    'initial': content_str
                }
            if baseimage:
                df_kwargs['baseimage'] = baseimage
            if maintainer:
                df_kwargs['maintainer'] = maintainer
            log.debug("Creating Dockerfile context: %s", df_kwargs)
            build_context = DockerContext(DockerFile(**df_kwargs))
            if file_list:
                for cached_src, tgt in file_list:
                    build_context.add(cached_src, arcname=tgt)
            build_context.finalize()

        elif dockerfile:
            build_context = DockerContext(dockerfile, finalize=True)

        else:
            raise SaltInvocationError("No Dockerfile input provided.")
    finally:
        if tmp_path:
            log.debug("Cleaning up temporary build dir %s.", tmp_path)
            shutil.rmtree(tmp_path, ignore_errors=True)

    m = get_client()
    c = m.default_client
    state_images = c.get_state_images()
    image_tag = '{0}:latest'.format(tag) if ':' not in tag else tag
    prev_image_id = state_images.get(image_tag)
    item_name = 'image:{0}'.format(image_tag)
    log.debug("Building image with tag %s.", image_tag)
    if not __opts__['test']:
        c.flush_log()
        try:
            image_id = c.build_from_context(build_context, tag, **clean_kwargs(**kwargs))
        except SUMMARY_EXCEPTIONS as e:
            return dict(result=False, item_id=item_name, changes={}, comment=_exc_message(e))
        if image_id:
            if image_id == prev_image_id:
                return dict(result=True, item_id=item_name, changes={}, comment=_get_success_comment({}))
            changes = {'image:{0}'.format(image_id): {'old': 'present' if prev_image_id else 'absent',
                                                      'new': 'built'}}
            res = dict(result=True, item_id=item_name, image_id=image_id, changes=changes, comment="Image built.")
            if show_log:
                res['log'] = c.flush_log()
            return res
        return dict(result=False, item_id=item_name, changes={}, comment="Error while building the image.")
    return dict(result=True, item_id=item_name, changes={}, comment="Image would have been built.")
