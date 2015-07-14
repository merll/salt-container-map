Salt Container-Map
==================

Configuration management and implicit dependency setup for Docker containers in SaltStack.
------------------------------------------------------------------------------------------

Project: https://github.com/merll/salt-container-map

Docs: Basic usage is provided in the [state module]
(http://salt-container-map.readthedocs.org/en/latest/api/saltcontainermap.states.html). Details about container
configurations are available in the [docs for Docker-Map]
(https://docker-map.readthedocs.org/en/latest/guide/containers/maps.html#container-landscapes-with-containermap).


Overview
========
This package contains SaltStack modules for configuring Docker containers. They do not replace,
but complement Salt's built-in `dockerio` module in the following aspects:

* Container dependencies that have to be followed during startup and shutdown do not have to be
  modelled via `require` or `require_in`. Instead, these are implicitly defined through their 
  shared volumes and links.
* For the purpose of sharing data between containers, virtual volumes can be created via a
  minimal runnable image (`tianon/true` obtained from the public Docker registry). These are
  considered during the dependency check and become adjusted with necessary file system permissions
  during startup.
* When the configuration of a container is modified, the affected containers and their dependents
  can automatically be shut down and recreated.
* Image updates can also result in an automated shutdown and recreation of containers and their
  dependents, without explicit `watch` or `onchanges`.
  
An example is documented in the state module.

Installation
============
Besides the usual package installation, a few simple post-installation steps are required. They are
described in the [docs](http://salt-container-map.readthedocs.org/en/latest/installation.html).

Modules
=======

Custom renderer
---------------
Container configurations can be set in both pillars and states. Pillars have the advantage that
they are loaded automatically before any state (e.g. `container_map.updated`) or execution module
uses it. Usually the disadvantage is that pillars cannot refer to other pillars. This package
however provides a custom renderer `lazy_yaml` along with custom tags `!pillar` and  `!grain`,
which are resolved to their values on the minion just before the container maps and their
configurations are instantiated.

By default, container maps are loaded from a pillar `container_maps`. This can be changed in the
configuration by setting

State and execution module
--------------------------
The modules distributed to the minions provide the functionality as outlined in the overview.
A usage example is included in the [state module documentation]
(http://salt-container-map.readthedocs.org/en/latest/api/saltcontainermap.states.html).
