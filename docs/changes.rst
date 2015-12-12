.. _change-history:

Change History
==============
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
