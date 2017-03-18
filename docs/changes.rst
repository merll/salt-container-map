.. _change-history:

Change History
==============
0.1.11
------
* Fixed access to a method removed from Docker-Map.

0.1.10
------
* Fixed import for compatibility with Docker-Map.

0.1.9
-----
* Added build function and built state.
* Added controlled shutdown to container removal (``remove_all_containers``).
* De-duplication of image names before pull.
* Configurable ``base_image`` and ``core_image``.
* Key ``out`` is only returned by module functions for non-empty output.
* Various bugfixes from `0.1.9b1`.

0.1.9b1
-------
* Added tag whitelist to ``cleanup_images`` module method and ``images_clean`` state.
* Adapted to changes in Docker-Map 0.6.6b1.

0.1.8
-----
* Skip registry authentication for prefixed images.
* Removed more keyword arguments attached by Salt.

0.1.7
-----
* Added registry authentication before pulling images in execution module.
* Separated IPv6 from IPv4 addresses in the client configuration.

0.1.6
-----
* Added ``extend_copy`` on map level, which allows for re-using extending maps under a different name.
* Added ``stop_timeout`` to ``remove_all_containers`` module function, using configuration.

0.1.5
-----
* Added wrapper for ``exec_create`` and ``exec_start`` for tracking post-container-start commands.
* Removed extra keyword arguments attached by Salt.

0.1.4
-----
* Improved behavior of watch directive on ``updated`` state.

0.1.3
-----
* Added ``signaled`` state.
* Fixed image update for extended configurations.

0.1.2
-----
* More sensitive error handling.

0.1.1
-----
* Added configuration for new DockerMap features.
* Minor cleanups.

0.1.0
-----
Initial release.
