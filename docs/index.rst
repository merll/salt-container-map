Salt Container-Map
==================

SaltStack includes the ``dockerio`` module for common actions on Docker containers. As an advantage to manual or
script-based approaches, this allows for a consistent configuration management. This package includes custom state
and execution modules named ``container_map``, complementing the built-in module with the following functionality:

* Container configurations (e.g. volumes, links, commands) can be managed in pillars, while the actions are created in
  state files.
* Dependencies between services are implicitly defined through links and shared volumes. Therefore, they are followed
  automatically during creation, start, stop, and removal of containers and do not have to be modelled explicitly via
  ``require`` or ``require_in``.
* Additional volumes can be created automatically to isolate shared resources.
* When images are updated on the Docker host, it is usually for the purpose of updating the containers depending on
  that image. This action can be triggered via ``watch`` in the ``dockerio`` module. With the ``container_map.update``
  state, the re-creation and restart takes places automatically, also considering dependencies.
* Changes in volumes, network parameters, and the command or entrypoint parameter also trigger a container re-creation
  when using ``container_map.update``.
* In case paths in the virtual filesystem of shared volumes between containers become inconsistent, e.g. due to manual
  actions or broken containers during a restart of the host system, containers are also re-created as far as necessary.

Along with the state and execution modules comes a custom renderer ``lazy_yaml``. It builds on Salt's built-in YAML
renderer, but adds two custom tags: ``!pillar`` and ``!grain``. The ``!pillar`` tag is to help the fact that usually
pillar files cannot include other pillar items. Instead of being processed by the template renderer, variables are
resolved to their actual values just before ``container_map`` uses them.

Contents:

.. toctree::
    :maxdepth: 2

    installation
    config
    api/saltcontainermap.states
    api/saltcontainermap.modules
    api/saltcontainermap.extmods
    changes


Indices and tables
==================

* :ref:`genindex`
* :ref:`search`
