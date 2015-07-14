Installation
============
The package consists of a custom renderer module, and two minion modules. The former is used by the
Salt master, the latter needs to be distributed to minions.

Salt master
-----------
Install the package by running

.. code-block:: bash

    pip install salt-container-map

Then place the installed modules in the appropriate Salt master directories, preferably as a
symlink. The easiest way of installing the modules is through the provided script
``install_container_map``, which attempts to look up the target directories in the master config
file. Since the script uses the Salt API for that purpose, the following locations are checked for
the configuration:

* The path described by the environment variable ``SALT_MASTER_CONFIG``;
* the directory from the environment variable ``SALT_CONFIG_DIR``, which may contain a file
  ``master``;
* and if none of these is available, the default ``/etc/salt/master``.

Salt minions
------------
Install the module dependency ``docker-map`` using ``pip``. For example, the following state can
accomplish this:

.. code-block:: yaml

    python_pip:
      pkg.installed:
      - name: curl

      cmd.run:
      - name: curl -s https://bootstrap.pypa.io/get-pip.py|python
      - unless:
        - which pip
      - reload_modules: True
      - require:
        - pkg: curl

    docker-map:
      pip.installed:
      - upgrade: True
      - require:
        - cmd: python_pip
      - reload_modules: True


If ``pip`` is already installed, you can skip the ``python_pip`` state.

Finally, distribute the modules from the master through ``saltutil.sync_all`` or
``state.highstate``, e.g.

.. code-block:: bash

    salt '*' saltutil.sync_all
