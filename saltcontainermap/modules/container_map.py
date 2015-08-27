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

from docker.errors import APIError, DockerException
from dockermap.functional import expand_type_name, resolve_deep
from dockermap.api import ClientConfiguration, ContainerMap, DockerClientWrapper, MappingDockerClient
from dockermap.map.container import MapIntegrityError
from msgpack import ExtType
from salt.exceptions import SaltInvocationError
from salt.ext import six

VIRTUAL_NAME = 'container_map'

TYPE_CONTAINER = 'container'
TYPE_IMAGE = 'image'

CONTAINER_ABSENT = 'absent'
CONTAINER_PRESENT = 'present'
CONTAINER_RUNNING = 'running'
CONTAINER_RESTARTED = 'restarted'
CONTAINER_STOPPED = 'stopped'
CONTAINER_UPDATED = 'updated'
IMAGE_ABSENT = 'missing'
IMAGE_PRESENT = 'present'
IMAGE_UPDATED = 'updated'

UPDATED_STATES = (CONTAINER_RUNNING, CONTAINER_PRESENT)
SUMMARY_EXCEPTIONS = (KeyError, ValueError, APIError, DockerException, MapIntegrityError)

log = logging.getLogger(__name__)


def __virtual__():
    return VIRTUAL_NAME


def _get_resolver(pillar, grain):
    class ValueNotFound(object):
        pass

    class ExtTypeResolver(object):
        def __init__(self, ext_type_pillar, ext_type_grain):
            self._code_pillar = ext_type_pillar
            self._code_grain = ext_type_grain
            self._get_pillar = __salt__['pillar.get']
            self._get_grain = __salt__['grains.get']

        def get(self, ext_data):
            code = ext_data.code
            if code == self._code_pillar:
                value = self._get_pillar(ext_data.data, ValueNotFound)
                if value is ValueNotFound:
                    raise KeyError("No pillar value '{0}' found.".format(ext_data.data))
                return value
            elif code == self._code_grain:
                value = self._get_grain(ext_data.data, ValueNotFound)
                if value is ValueNotFound:
                    raise KeyError("No grain value '{0}' found.".format(ext_data.data))
                return value
            return ext_data

    return ExtTypeResolver(pillar, grain)


def _split_map_name(name, map_name):
    if not map_name:
        container_map, __, container_name = name.partition('.')
        return container_name, container_map or None
    return name, map_name


def _get_auth_data(registry):
    auth_data = __salt__['pillar.get']('docker-registries')
    if isinstance(auth_data, dict):
        registry_auth = auth_data.get(registry)
        if registry_auth:
            log.debug("Found authentication data for registry %s, user %s.", registry, registry_auth.get('username'))
            return auth_data.get(registry)
    log.debug("No authentication data for registry %s found.", registry)
    return None


def _create_client(initial_maps):
    """
    :type initial_maps: dict[unicode, ContainerMap]
    :rtype: SaltDockerMap
    """
    class SaltDockerClient(DockerClientWrapper):
        """
        Enhanced Docker client for SaltStack, which maintains something similar to a change log based on container actions.
        """
        def __init__(self, *args, **kwargs):
            super(SaltDockerClient, self).__init__(*args, **kwargs)
            self._last_action = None
            self._changes = {}
            self._state_images = None

        def _update_attempt(self, item_type, name, old_state, new_state):
            self._last_action = dict(item_type=item_type, item_id=name, old=old_state, new=new_state)

        def _update_status(self, item_type, name, old_state, new_state):
            key = '{0}:{1}'.format(item_type, name)
            state = self._changes.get(key)
            if state:
                old_val = state['old']
                if item_type == TYPE_CONTAINER:
                    if old_val == CONTAINER_ABSENT and new_state == CONTAINER_ABSENT:
                        del self._changes[key]
                    elif old_val in UPDATED_STATES and new_state in UPDATED_STATES:
                        state['new'] = CONTAINER_UPDATED
                    else:
                        state['new'] = new_state
                else:
                    state['new'] = new_state
            else:
                state = {'old': old_state, 'new': new_state}
                self._changes[key] = state
            self._last_action = None

        def create_container(self, image, *args, **kwargs):
            if __opts__['test']:
                res = {'Name': '/__unknown__', 'Id': '__unknown__'}
            else:
                self._update_attempt(TYPE_CONTAINER, kwargs.get('name', '__unknown__'), CONTAINER_ABSENT, CONTAINER_PRESENT)
                res = super(SaltDockerClient, self).create_container(image, *args, **kwargs)
            self._update_status(TYPE_CONTAINER, kwargs.get('name', res['Id']), CONTAINER_ABSENT, CONTAINER_PRESENT)
            return res

        def start(self, container, *args, **kwargs):
            if not __opts__['test']:
                self._update_attempt(TYPE_CONTAINER, container, CONTAINER_PRESENT, CONTAINER_RUNNING)
                super(SaltDockerClient, self).start(container, *args, **kwargs)
            self._update_status(TYPE_CONTAINER, container, CONTAINER_PRESENT, CONTAINER_RUNNING)

        def restart(self, container, *args, **kwargs):
            if not __opts__['test']:
                self._update_attempt(TYPE_CONTAINER, container, CONTAINER_RUNNING, CONTAINER_RESTARTED)
                super(SaltDockerClient, self).restart(container, *args, **kwargs)
            self._update_status(TYPE_CONTAINER, container, CONTAINER_RUNNING, CONTAINER_RESTARTED)

        def stop(self, container, *args, **kwargs):
            if not __opts__['test']:
                self._update_attempt(TYPE_CONTAINER, container, CONTAINER_RUNNING, CONTAINER_STOPPED)
                super(SaltDockerClient, self).stop(container, *args, **kwargs)
            self._update_status(TYPE_CONTAINER, container, CONTAINER_RUNNING, CONTAINER_STOPPED)

        def remove_container(self, container, *args, **kwargs):
            if not __opts__['test']:
                self._update_attempt(TYPE_CONTAINER, container, CONTAINER_PRESENT, CONTAINER_ABSENT)
                super(SaltDockerClient, self).remove_container(container, *args, **kwargs)
            self._update_status(TYPE_CONTAINER, container, CONTAINER_PRESENT, CONTAINER_ABSENT)

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

        def login(self, username, password=None, email=None, registry=None, **kwargs):
            if registry:
                auth_data = _get_auth_data(registry)
                if isinstance(auth_data, dict):
                    if not username:
                        username = auth_data.get('username')
                    if not password:
                        password = auth_data.get('password')
                    if not email:
                        email = auth_data.get('email')
                    return super(SaltDockerClient, self).login(username, password, email, registry, **kwargs)
            return super(SaltDockerClient, self).login(username, password, email, registry, **kwargs)

        def pull(self, repository, tag=None, *args, **kwargs):
            if self._state_images is None:
                self.images()
            full_image = '{0}:{1}'.format(repository, tag) if tag else repository
            prev_id = self._state_images.get(full_image)
            if prev_id:
                prev_status = IMAGE_PRESENT
                new_status = IMAGE_UPDATED
            else:
                prev_status = IMAGE_ABSENT
                new_status = IMAGE_PRESENT
            if __opts__['test']:
                res = None
            else:
                self._update_attempt(TYPE_IMAGE, full_image, prev_status, new_status)
                res = super(SaltDockerClient, self).pull(repository, tag, *args, **kwargs)
                updated_images = super(SaltDockerClient, self).images(repository)
                if updated_images:
                    new_image = updated_images[0]
                    new_id = new_image['Id']
                    if prev_id and prev_id == new_id:
                        new_status = IMAGE_PRESENT
                    new_tags = new_image.get('RepoTags')
                    if new_tags:
                        self._state_images.update({tag: new_id for tag in new_tags})
                else:
                    new_status = IMAGE_ABSENT
            if prev_status != new_status:
                self._update_status(TYPE_IMAGE, full_image, prev_status, new_status)
            else:
                self._last_action = None
            return res

        def remove_image(self, image, *args, **kwargs):
            if __opts__['test']:
                res = None
            else:
                self._update_attempt(TYPE_IMAGE, image, IMAGE_PRESENT, IMAGE_ABSENT)
                res = super(SaltDockerClient, self).remove_image(image, *args, **kwargs)
            self._update_status(TYPE_IMAGE, image, IMAGE_PRESENT, IMAGE_ABSENT)
            return res

        def flush_changes(self):
            """
            Returns the changed items and clears the change log.

            :return: dict[unicode, dict[unicode, unicode]]
            """
            changes = self._changes
            self._last_action = None
            self._changes = {}
            return changes

        @property
        def last_action(self):
            return self._last_action

    class SaltDockerClientConfig(ClientConfiguration):
        """
        Enhanced Docker client configuration object for SaltStack. Maps the interfaces directly to the 'ip_interfaces'
        generated from grains.
        """
        client_constructor = SaltDockerClient

        def __init__(self, *args, **kwargs):
            config_get = __salt__['config.get']
            grains_get = __salt__['grains.get']
            pillar_get = __salt__['pillar.get']
            for kw, ck, pk in (('base_url', 'docker.url', 'docker:url'),
                               ('timeout', 'docker.timeout', 'docker:timeout'),
                               ('version', 'docker.version', 'docker:version'),
                               ('stop_timeout', None, 'docker:stop_timeout'),
                               ('wait_timeout', None, 'docker:wait_timeout')):
                if kw not in kwargs:
                    pillar_value = pillar_get(pk, None)
                    if pillar_value is not None:
                        kwargs[kw] = pillar_value
                    elif ck:
                        config_value = config_get(ck, None)
                        if config_value is not None:
                            kwargs[kw] = config_value
            if 'base_url' not in kwargs and 'DOCKER_HOST' in os.environ:
                kwargs['base_url'] = os.environ['DOCKER_HOST']
            if 'domainname' not in kwargs:
                kwargs['domainname'] = (pillar_get('container_map:domainname') or grains_get('domain') or
                                        grains_get('container_map:domainname'))
            interfaces = {if_name: if_addresses[0]
                          for if_name, if_addresses in six.iteritems(grains_get('ip_interfaces', {})) if if_addresses}
            aliases = (grains_get('container_map:interface_aliases') or pillar_get('container_map:interface_aliases') or
                       config_get('container_map.interface_aliases', {}))
            aliased_if = {alias: interfaces.get(if_name)
                          for alias, if_name in six.iteritems(aliases)}
            interfaces.update(aliased_if)
            kwargs['interfaces'] = interfaces
            super(SaltDockerClientConfig, self).__init__(*args, **kwargs)

    class SaltDockerMap(MappingDockerClient):
        """
        Adapted :class:`~dockermap.map.client.MappingDockerClient`.
        """
        configuration_class = SaltDockerClientConfig

        def __init__(self, *args, **kwargs):
            super(SaltDockerMap, self).__init__(*args, **kwargs)
            default_name = self.policy_class.get_default_client_name()
            self._default_client_name = default_name
            self._default_config = self.clients[default_name]

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
        return dict(result=True, item_id=item_id, changes=changes, comment=comment, out=output)

    fail = client.last_action or {}
    changes = client.flush_changes()
    error_message = ''.join(traceback.format_exception_only(type(exception), exception))
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


def get_client():
    '''
    Creates and returns the client. The client is only instantiated once and not re-created for multiple requests.
    '''
    client = __context__.get('container_map.client')
    if client:
        return client

    config_get = __salt__['config.get']
    pillar_get = __salt__['pillar.get']
    log.debug("Configuring ExtType.")
    ext_resolver = _get_resolver(config_get('lazy_yaml.ext_code_pillar', 10),
                                 config_get('lazy_yaml.ext_code_grain', 11))
    resolve_dict = {expand_type_name(ExtType): ext_resolver.get}
    log.debug("Loading container maps.")
    pillar_name = config_get('container_map.pillar_name', 'container_maps')
    map_dicts = pillar_get(pillar_name, {})
    all_maps = {}
    attached_parent_name = pillar_get('container_map:use_attached_parent_name', None)
    if attached_parent_name is None:
        attached_parent_name = config_get('container_map:use_attached_parent_name', False)
    skip_checks = pillar_get('container_map:skip_checks', None)
    if skip_checks is None:
        skip_checks = config_get('container_map.skip_checks', False)
    if map_dicts:
        log.info("Initializing container maps: %s", ', '.join(map_dicts.keys()))
        merge_maps = defaultdict(list)
        for map_name, map_content in six.iteritems(map_dicts):
            resolved_content = resolve_deep(map_content, types=resolve_dict)
            merge_into = resolved_content.pop('merge_into', None)
            if merge_into:
                merge_maps[merge_into].append(resolved_content)
            else:
                check_integrity = not resolved_content.pop('skip_check', skip_checks)
                try:
                    a_p_name = resolved_content.pop('use_attached_parent_name', attached_parent_name)
                    c_map = ContainerMap(map_name, resolved_content, check_integrity=check_integrity,
                                         use_attached_parent_name=a_p_name)
                    all_maps[map_name] = c_map
                except MapIntegrityError as e:
                    log.error("Skipping map %s because of integrity error: %s", map_name, e.message)
        for map_name, merge_contents in six.iteritems(merge_maps):
            merge_into_map = all_maps.get(map_name)
            for merge_content in merge_contents:
                if merge_into_map:
                    merge_into_map.merge(merge_content, lists_only=merge_content.pop('merge_lists_only', False))
                else:
                    log.error("Map %s is not available for merging into: %s", merge_into_map, map_name)

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
                name, traceback.format_exception_only(type(e), e)), out=traceback.format_exc())
    elif not ignore_existing:
        return dict(result=False, item_id=name, changes={},
                    comment="A map with name '{0}' is already loaded.".format(name))
    return dict(result=True, item_id=name, changes={}, comment="Map '{0}' loaded.".format(name), out=None)


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
            name, traceback.format_exception_only(type(e), e)), out=traceback.format_exc())
    return dict(result=True, item_id=name, changes={}, comment="Map '{0}' loaded.".format(name), out=None)


def create(container, instances=None, map_name=None, **kwargs):
    '''
    Creates a container, along with its dependencies. Existing containers are not re-created.

    name
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    kwargs
        Extra keyword arguments for the container creation.
    '''
    container_name, container_map = _split_map_name(container, map_name)
    m = get_client()
    try:
        m.create(container_name, instances=instances, map_name=container_map, **kwargs)
    except SUMMARY_EXCEPTIONS as e:
        return _status(m.default_client, exception=e)
    return _status(m.default_client, item_id=container)


def start(container, instances=None, map_name=None, **kwargs):
    '''
    Starts a container, along with its dependencies. Fails on non-existing containers, but not on containers that are
    already started.

    name
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    kwargs
        Extra keyword arguments for the container start.
    '''
    container_name, container_map = _split_map_name(container, map_name)
    m = get_client()
    try:
        m.start(container_name, instances=instances, map_name=container_map, **kwargs)
    except SUMMARY_EXCEPTIONS as e:
        return _status(m.default_client, exception=e)
    return _status(m.default_client, item_id=container)


def stop(container, instances=None, map_name=None, **kwargs):
    '''
    Stops a container, along with its dependent containers. Ignores non-existing or non-running containers.

    name
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    kwargs
        Extra keyword arguments for the container stop.
    '''
    container_name, container_map = _split_map_name(container, map_name)
    m = get_client()
    try:
        m.stop(container_name, instances=instances, map_name=container_map, **kwargs)
    except SUMMARY_EXCEPTIONS as e:
        return _status(m.default_client, exception=e)
    return _status(m.default_client, item_id=container)


def remove(container, instances=None, map_name=None, **kwargs):
    '''
    Removes a container, along with its dependent containers. Ignores non-existing containers, but fails on running
    containers.

    name
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    kwargs
        Extra keyword arguments for the container removal.
    '''
    container_name, container_map = _split_map_name(container, map_name)
    m = get_client()
    try:
        m.remove(container_name, instances=instances, map_name=container_map, **kwargs)
    except SUMMARY_EXCEPTIONS as e:
        return _status(m.default_client, exception=e)
    return _status(m.default_client, item_id=container)


def restart(container, instances=None, map_name=None, **kwargs):
    '''
    Restarts a container.

    name
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    kwargs
        Extra keyword arguments for the container restart.
    '''
    container_name, container_map = _split_map_name(container, map_name)
    m = get_client()
    try:
        m.restart(container_name, instances=instances, map_name=container_map, **kwargs)
    except SUMMARY_EXCEPTIONS as e:
        return _status(m.default_client, exception=e)
    return _status(m.default_client, item_id=container)


def startup(container, instances=None, map_name=None):
    '''
    Creates and starts a container as needed, along with its dependencies. Ignores running containers.

    name
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    '''
    container_name, container_map = _split_map_name(container, map_name)
    m = get_client()
    try:
        m.startup(container_name, instances=instances, map_name=container_map)
    except SUMMARY_EXCEPTIONS as e:
        return _status(m.default_client, exception=e)
    return _status(m.default_client, item_id=container)


def shutdown(container, instances=None, map_name=None):
    '''
    Stops and removes a container as needed, along with its dependent containers. Ignores non-existing containers.

    name
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    '''
    container_name, container_map = _split_map_name(container, map_name)
    m = get_client()
    try:
        m.shutdown(container_name, instances=instances, map_name=container_map)
    except SUMMARY_EXCEPTIONS as e:
        return _status(m.default_client, exception=e)
    return _status(m.default_client, item_id=container)


def update(container, instances=None, map_name=None):
    '''
    Ensures that a container is up-to-date, i.e.
    * the image id corresponds with the image tag from the configuration
    * the existing container still has access to all dependent volumes
    * linked containers are available
    * command, entrypoint, or environment have not been changed.

    Non-existing containers are created and started. Outdated containers are removed and re-created and restarted along
    the dependency path.

    name
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    '''
    container_name, container_map = _split_map_name(container, map_name)
    m = get_client()
    try:
        m.update(container_name, instances=instances, map_name=container_map)
    except SUMMARY_EXCEPTIONS as e:
        return _status(m.default_client, exception=e)
    return _status(m.default_client, item_id=container)


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
    try:
        c.cleanup_containers(include_initial=include_initial, exclude=excluded_names)
    except SUMMARY_EXCEPTIONS as e:
        return _status(c, exception=e)
    return _status(c)


def cleanup_images(remove_old=False):
    '''
    Removes all images from the host which are not in use by any container and have no tag. Optionally can also remove
    images with a repository tag that is not ``latest``.

    remove_old : False
        Remove images that have a tag, but not ``latest``. Does not affect additional (e.g. version) tags of ``latest``
        images.
    '''
    c = get_client().default_client
    try:
        c.cleanup_images(remove_old=remove_old)
    except SUMMARY_EXCEPTIONS as e:
        return _status(c, exception=e)
    return _status(c)


def remove_all_containers():
    '''
    Removes all containers from the host.
    '''
    c = get_client().default_client
    try:
        c.remove_all_containers()
    except SUMMARY_EXCEPTIONS as e:
        return _status(c, exception=e)
    return _status(c)


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
    container_name, container_map = _split_map_name(container, map_name)
    m = get_client()
    try:
        m.call(action_name, container_name, instances=instances, map_name=container_map, **kwargs)
    except SUMMARY_EXCEPTIONS as e:
        return _status(m.default_client, exception=e)
    return _status(m.default_client, item_id=container)


def script(container, instance=None, map_name=None, wait_timeout=10, autoremove_before=False, autoremove_after=True,
           source=None, saltenv='base', template=None, contents=None, content_pillar=None, path=None, file_mode=None,
           dir_mode=None, user=None, group=None, entrypoint=None, command_format=None,
           container_script_dir='/tmp/script_run', timestamps=None, tail='all'):
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
        Script source file (e.g. ``salt://...`` for a script file loaded form the master).
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
        Directory to use as moint point inside the container.
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
            f, script_path = tempfile.mkstemp(dir=path)
            log.debug("Copying script to temporary file %s.", script_path)
            f.close()
            if template:
                __salt__['cp.get_template'](source, script_path, template=template, saltenv=saltenv)
            else:
                cached_name = __salt__['cp.cache_file'](source, saltenv)
                if not cached_name:
                    raise SaltInvocationError("Failed to cache source file {0}.".format(source))
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

        container_name, container_map = _split_map_name(container, map_name)
        m = get_client()
        client_name = m.default_client_name
        policy = m.get_policy()
        policy.remove_existing_before = autoremove_before
        policy.remove_created_after = autoremove_after

        if script_dir:
            ch_user = user or m.maps[container_map].containers[container_name].user
            log.debug("Changing user of %s to %s.", script_dir, ch_user)
            __salt__['file.check_perms'](script_dir, {}, ch_user, group, dir_mode)
            if script_path:
                log.debug("Changing user of %s to %s.", script_path, ch_user)
                __salt__['file.check_perms'](script_path, {}, ch_user, group, file_mode)
        try:
            log.debug("Running script in container %s.%s.\nHost path: %s\nEntrypoint: %s\nCommand template: %s",
                      container_map, container_name, script_path or script_dir, entrypoint, command_format)
            res = m.run_script(container_name, instance=instance, map_name=container_map,
                               script_path=script_path or script_dir,
                               entrypoint=entrypoint, command_format=command_format, wait_timeout=wait_timeout,
                               container_script_dir=container_script_dir, timestamps=timestamps, tail=tail)
            out = res.get(client_name) if res else None
        except SUMMARY_EXCEPTIONS as e:
            return _status(m.default_client, exception=e)
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
    return _status(m.default_client, item_id=container, output=out)


def pull_latest_images(map_name=None, map_names=None, utility_images=True, insecure_registry=False):
    '''
    Updates all images on a map to their latest version or the specified tag.

    map_name
        Container map name.
    map_names
        Multiple container map names. Can be used instead of, or in conjunction with ``map_name``.
    utility_images : True
        Unless set to ``False``, also updates utility images such as ``busybox`` and ``tianon/true``.
    insecure_registry : False
        Allow `insecure` registries for retrieving images.
    '''
    def _pull(i_name):
        try:
            images.ensure_image(i_name, pull_latest=True, insecure_registry=insecure_registry)
        except SUMMARY_EXCEPTIONS as e:
            error_message = ''.join(traceback.format_exception_only(type(e), e))
            errors[i_name] = error_message
        else:
            status[i_name] = "Image updated."

    m = get_client()
    if map_names:
        names = map_names[:]
        if map_name:
            names.append(map_name)
    elif map_name:
        if map_name == '__all__':
            names = list(m.maps.keys())
        else:
            names = [map_name]
    else:
        names = None
    policy = m.get_policy()
    images = policy.images[m.default_client_name]
    status = {}
    errors = {}
    if utility_images:
        _pull(policy.base_image)
        _pull(policy.core_image)
    if names:
        for map_name in names:
            c_map = m.maps[map_name]
            for c_name, config in c_map:
                image_name = policy.iname(c_map, config.image or c_name)
                _pull(image_name)
    if errors:
        if status:
            comment = "At least one image failed to update."
        else:
            comment = "All images failed to update."
        status.update(errors)
        return dict(result=False, item_id=map_name, changes=status, comment=comment, out=errors)
    return dict(result=True, item_id=map_name, changes=status, comment="All images updated", out=None)


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
        result = client.login(username, password, email, registry=registry, reauth=reauth, **kwargs)
    except SUMMARY_EXCEPTIONS as e:
        error_message = ''.join(traceback.format_exception_only(type(e), e))
        return dict(result=False, item_id=registry, changes={}, comment=error_message, out=None)
    return dict(result=result, item_id=registry, changes={}, comment="Client logged in.", out=None)
