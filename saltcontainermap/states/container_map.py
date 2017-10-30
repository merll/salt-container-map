# -*- coding: utf-8 -*-
'''
Module for managing containers, configured through `Docker-Map <https://github.com/merll/docker-map>`_, along with
dependencies in Salt states. It complements Salt's ``dockerng`` module with the following functionality:

* Implicit dependency check of containers based on volumes and links.
* Automated provision of containers for the purpose of selectively sharing data between containers (`attached`
  containers).
* Automated re-creation of containers when their running state diverts from the configuration in

  * image id,
  * volume paths,
  * ports,
  * entrypoint, command, or environment.

Maps can be stored in a pillar ``container_maps`` (or any other name set in the configuration variable
``container_map.pillar_name``). When using the ``lazy_yaml`` renderer, pillar values can be used as far as custom
tags are valid in YAML. The ``lazy_yaml`` module has to be accessible by the master.

.. code-block:: yaml

  #!lazy_yaml

  container_maps:
    webapp:
      repository: registry.example.com
      host_root: /var/lib/site
      containers:
        web_server:
          image: nginx
          binds:
            !pillar web:host_paths:config:
              - !pillar web:host_paths:config
              - ro
          uses: app_server_socket
          attaches: web_log
          exposes:
            80: !pillar web:port_http
            443: !pillar web:port_https
        app_server:
          image: app
          instances:
            - instance1
            - instance2
          binds:
            - app_config: ro
            - app_data:
          attaches:
            - app_log
            - app_server_socket
          user: !pillar app:user
          permissions: u=rwX,g=rX,o=
      volumes:
        web_log: !pillar web:container_paths:log
        app_server_socket: !pillar app:container_paths:socket
        app_config: !pillar app:container_paths:config
        app_log: !pillar app:container_paths:log
        app_data: !pillar app:container_paths:data
      host:
        app_config:
          instance1: !pillar app1:host_paths:config
          instance2: !pillar app2:host_paths:config
        app_data:
          instance1: !pillar app1:host_paths:data
          instance2: !pillar app2:host_paths:data

For skipping the dependency check of incomplete maps, add ``skip_check: True`` on the same level as ``containers``.

For merging a pillar into an existing one, use ``merge_into``, e.g.

.. code-block:: yaml

    container_map:
      extra_app:
        merge_into: webapp
        containers:
          ...

During the pillar set up, maps can also copied and extended from others using ``extend_copy``, so that per-application
adaptions are possible. For example

.. code-block: yaml

    container_map:
      webapp_custom:
        extend_copy: webapp
        containers:
         ...

will create a map ``webapp_custom`` that includes all containers from ``webapp``. It also contains all contents that
have been merged into ``webapp``, as ``merge_into`` on extended maps is processed beforehand.

As an alternative to the pillar setup, ``set_up`` / ``merged`` can be used to add container configurations, but these
need to be set as a prerequisite to any action.

Aforementioned example will ensure that the following state starts containers in the required order and maps host
volumes to the ``web_server`` container, and each of the instances ``app_config.instance1`` and
``app_config.instance2``.

When the image ``app`` changes, on re-execution of the state containers are stopped, removed, re-created and restarted
as necessary.

.. code-block:: yaml

    webapp.web_server:
      container_map.updated: []


:meth:`updated` also accepts a parameter ``reload_signal``. This is only used in conjunction with a ``watch`` directive,
if the container was not restarted, i.e. likely just need to load its configuration. A useful value in this case is
typically ``SIGHUP``.

.. code-block:: yaml

    webapp.web_server:
      container_map.updated:
      - reload_signal: SIGHUP
      - watch:
        - file: webapp_config


For a full description of `Docker-Map <https://github.com/merll/docker-map>`_, please refer to
`its documentation <http://docker-map.readthedocs.org/en/latest/>`_.
'''
from __future__ import unicode_literals

from salt.utils import clean_kwargs


def set_up(name, containers=None, volumes=None, host=None, host_root=None, repository=None, default_domain=None,
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
    res = __salt__['container_map.setup'](name, containers=containers, volumes=volumes, host=host, host_root=host_root,
                                          repository=repository, default_domain=default_domain,
                                          check_integrity=check_integrity, ignore_existing=ignore_existing)
    res['name'] = res['item_id']
    return res


def merged(name, target_map, containers=None, volumes=None, host=None, host_root=None, repository=None,
           default_domain=None, lists_only=False):
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
    res = __salt__['container_map.merge'](target_map, containers=containers, volumes=volumes, host=host,
                                          host_root=host_root, repository=repository, default_domain=default_domain,
                                          lists_only=lists_only)
    res['name'] = res['item_id']
    return res


def created(name, instances=None, map_name=None, extra_kwargs=None):
    '''
    Ensures that a container exists, along with its dependencies.

    name
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    extra_kwargs
        Extra keyword arguments for the container creation.
    '''
    create_kwargs = extra_kwargs or {}
    res = __salt__['container_map.create'](name, instances=instances, map_name=map_name, **create_kwargs)
    res.update(name=name, instances=instances, map_name=map_name)
    return res


def started(name, instances=None, map_name=None, extra_kwargs=None):
    '''
    Ensures that a container is started, along with its dependencies.

    name
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    extra_kwargs
        Extra keyword arguments for the container start.
    '''
    start_kwargs = extra_kwargs or {}
    res = __salt__['container_map.start'](name, instances=instances, map_name=map_name, **start_kwargs)
    res.update(name=name, instances=instances, map_name=map_name)
    return res


def restarted(name, instances=None, map_name=None, extra_kwargs=None):
    '''
    Restarts a container.

    name
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    extra_kwargs
        Extra keyword arguments for the container restart.
    '''
    restart_kwargs = extra_kwargs or {}
    res = __salt__['container_map.restart'](name, instances=instances, map_name=map_name, **restart_kwargs)
    res.update(name=name, instances=instances, map_name=map_name)
    return res


def stopped(name, instances=None, map_name=None, extra_kwargs=None):
    '''
    Ensures that a container is stopped, along with its dependent containers.

    name
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    extra_kwargs
        Extra keyword arguments for the container stop.
    '''
    stop_kwargs = extra_kwargs or {}
    res = __salt__['container_map.stop'](name, instances=instances, map_name=map_name, **stop_kwargs)
    res.update(name=name, instances=instances, map_name=map_name)
    return res


def removed(name, instances=None, map_name=None, extra_kwargs=None):
    '''
    Ensures that a container is removed, along with its dependent containers.

    name
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    extra_kwargs
        Extra keyword arguments for the container removal.
    '''
    remove_kwargs = extra_kwargs or {}
    res = __salt__['container_map.remove'](name, instances=instances, map_name=map_name, **remove_kwargs)
    res.update(name=name, instances=instances, map_name=map_name)
    return res


def started_up(name, instances=None, map_name=None):
    '''
    Ensures that a container exists and that it is started, along with its dependencies.

    name
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    '''
    res = __salt__['container_map.startup'](name, instances=instances, map_name=map_name)
    res.update(name=name, instances=instances, map_name=map_name)
    return res


def shut_down(name, instances=None, map_name=None):
    '''
    Ensures that a container is stopped and removed, along with its dependent containers.

    name
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    '''
    res = __salt__['container_map.shutdown'](name, instances=instances, map_name=map_name)
    res.update(name=name, instances=instances, map_name=map_name)
    return res


def updated(name, instances=None, map_name=None, reload_signal=None, send_signal=False, **kwargs):
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
    reload_signal
        Optional signal to send to the main process for reloading.
    send_signal : False
        Whether to send the ``reload_signal``. Set to ``True`` by the ``watch`` directive.
    '''
    if send_signal:
        signal = reload_signal
    else:
        signal = None
    res = __salt__['container_map.update'](name, instances=instances, map_name=map_name, reload_signal=signal)
    res.update(name=name, instances=instances, map_name=map_name)
    return res


def signaled(name, instances=None, map_name=None, signal=None):
    """
    Sends a signal to a container. By default this is SIGKILL, but can be set to other signals, e.g. SIGHUP for
    reloading configurations.

    name
        Container configuration name.
    instances
        Optional list of instance names.
    map_name
        Container map name.
    signal
        Signal name or number.
    """
    res = __salt__['container_map.kill'](name, instances=instances, map_name=map_name, signal=signal)
    res.update(name=name, instances=instances, map_name=map_name)
    return res


def all_removed(name, **kwargs):
    '''
    Removes all containers from the host. Note this also applies to containers that are not on any map.

    name
        State name - has no effect.
    kwargs
        Keyword arguments forwarded to ``container_map.remove_all_containers``.
    '''
    res = __salt__['container_map.remove_all_containers'](**clean_kwargs(**kwargs))
    res['name'] = '__all__'
    return res


def containers_clean(name, include_initial=False, exclude=None):
    '''
    Removes all containers from the host which are not running, not attached volume containers, and not marked as
    persistent. Note this also applies to containers that are not on any map.

    name
        State name - has no effect.
    include_initial : False
        If set to ``True``, also removes containers that have never been running.
    exclude
        List of container names or ids to exclude from the removal.
    '''
    res = __salt__['container_map.cleanup_containers'](include_initial=include_initial, exclude=exclude)
    res['name'] = '__all__'
    return res


def images_clean(name, remove_old=False, keep_tags=None):
    '''
    Removes all images from the host which are not in use by any container and have no tag. Optionally can also remove
    images with a repository tag that is not ``latest``, or all tags which are not in the specified whitelist.

    name
        State name - has no effect.
    remove_old : False
        Remove images that have a tag, but not ``latest``. Does not affect additional (e.g. version) tags of ``latest``
        images.
    keep_tags
        Remove images that have none of the specified tags.
    '''
    res = __salt__['container_map.cleanup_images'](remove_old=remove_old, keep_tags=keep_tags)
    res['name'] = '__all__'
    return res


def images_updated(name, map_name=None, utility_images=True, insecure_registry=False):
    '''
    Ensures that all images on a map are updated to their latest version or the specified tag.

    name
        State name - has no effect.
    map_name
        Container map name.
    map_names
        Multiple container map names. Can be used instead of, or in conjunction with ``map_name``.
    utility_images : True
        Unless set to ``False``, also updates utility images such as ``busybox`` and ``tianon/true``.
    insecure_registry : False
        Allow `insecure` registries for retrieving images.
    '''
    res = __salt__['container_map.pull_latest_images'](name, map_name=map_name,
                                                       utility_images=utility_images,
                                                       insecure_registry=insecure_registry)
    res['name'] = map_name or '__base__'
    return res


def logged_in(name, username=None, password=None, email=None, reauth=False):
    '''
    Ensures authentication to a registry. All parameters are optional, and in case they are no provided information
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
    '''
    res = __salt__['container_map.login'](name, username=username, password=password, email=email, reauth=reauth)
    res['name'] = name
    return res


def built(name, **kwargs):
    '''
    name
        Image tag to apply.
    ignore_existing : False
        Rebuild the image if it exists. Note this does not imply ``nocache``, so might not actually generate a new
        image.
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
    baseimage:
        Image to base the build on. Ignored if ``source`` is used. Can also be included directly
        using the ``FROM`` Dockerfile command.
    maintainer:
        Maintainer to state in the image. Ignored if ``source`` is used. Can also be included
        using the ``MAINTAINER`` Dockerfile command.
    kwargs
        Additional keyword arguments for building the Docker image.
    '''
    ignore_existing = kwargs.pop('ignore_existing', False)
    if not ignore_existing and __salt__['container_map.image_tag_exists'](name):
        return dict(result=True, name=name, changes={}, comment="Image exists.")

    res = __salt__['container_map.build'](name, **kwargs)
    res['name'] = name
    return res


def mod_watch(name, sfun=None, **kwargs):
    if sfun == 'updated':
        kwargs['send_signal'] = True
        return updated(name, **kwargs)
    elif sfun == 'built':
        kwargs['ignore_existing'] = True
        return built(name, **kwargs)

    return dict(name=name, result=False, changes={}, comment='watch requisite is not implemented for {0}'.format(sfun))
