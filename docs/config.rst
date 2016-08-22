Configuration
=============
There are a few optional configuration settings, that adjust the behavior of the provided modules. For all of them,
the order of precedence is as follows, where available:

* Pillar values have the highest priority.
* In absence of the pillar value, a grain value is read.
* If there is no matching grain, the configuration option applies.
* Where applicable, a default value is used in case no other setting is available.

+----------------------------------------+----------------------------------------+------------------------------------------------------------------+---------------------------------+------------------------+
| Pillar / Grain                         | Config                                 | Description                                                      | Default                         | Comment                |
+========================================+========================================+==================================================================+=================================+========================+
| docker:url                             | docker.url                             | Docker API URL.                                                  | http+unix://var/run/docker.sock | same as for `dockerio` |
+----------------------------------------+----------------------------------------+------------------------------------------------------------------+---------------------------------+------------------------+
| docker:timeout                         | docker.timeout                         | Docker API request timeout.                                      | 60                              |                        |
+----------------------------------------+----------------------------------------+------------------------------------------------------------------+---------------------------------+------------------------+
| docker:version                         | docker.version                         | Docker API version.                                              | depends on `docker-py` version  |                        |
+----------------------------------------+----------------------------------------+------------------------------------------------------------------+---------------------------------+------------------------+
| docker-registries                      |                                        | Authentication data for Docker registries.                       |                                 |                        |
+----------------------------------------+----------------------------------------+------------------------------------------------------------------+---------------------------------+------------------------+
| docker:wait_timeout                    | docker.wait_timeout                    | More specific timeout for waiting for a container to finish.     | 60                              |                        |
+----------------------------------------+----------------------------------------+------------------------------------------------------------------+---------------------------------+------------------------+
| docker:stop_timeout                    | docker.stop_timeout                    | Timeout for stopping a container. More precisely, time span      | 10                              |                        |
|                                        |                                        | between sending SIGINT and SIGKILL to the main process.          |                                 |                        |
+----------------------------------------+----------------------------------------+------------------------------------------------------------------+---------------------------------+------------------------+
| container_map:domainname               |                                        | Domain name for creating containers.                             |                                 |                        |
| (*grain*: domain)                      |                                        |                                                                  |                                 |                        |
+----------------------------------------+----------------------------------------+------------------------------------------------------------------+---------------------------------+------------------------+
| container_map:interface_aliases        | container_map.interface_aliases        | Mapping network interface alias names to actual interface names. |                                 | Example:               |
|                                        |                                        |                                                                  |                                 |                        |
|                                        |                                        |                                                                  |                                 | ``private: eth1``      |
|                                        |                                        |                                                                  |                                 | ``public: eth0``       |
+----------------------------------------+----------------------------------------+------------------------------------------------------------------+---------------------------------+------------------------+
| container_map:use_attached_parent_name | container_map.use_attached_parent_name | Include the name of the parent container in attached             | False                           | ``public: eth0``       |
|                                        |                                        | containers' names.                                               |                                 |                        |
+----------------------------------------+----------------------------------------+------------------------------------------------------------------+---------------------------------+------------------------+
| container_map:skip_checks              | container_map.skip_checks              | Skip integrity checks when loading container maps.               | False                           | ``skip_check`` can be  |
|                                        |                                        |                                                                  |                                 | set to ``True`` on map |
+----------------------------------------+----------------------------------------+------------------------------------------------------------------+---------------------------------+------------------------+
| container_map:raise_map_errors         | container_map.raise_map_errors         | For maps loaded from pillars, raise errors immediately.          | True                            | If ``False``, only     |
|                                        |                                        |                                                                  |                                 | appears in minion log  |
+----------------------------------------+----------------------------------------+------------------------------------------------------------------+---------------------------------+------------------------+
|                                        | container_map.pillar_name              | Pillar to load container maps from on module init.               | container_maps                  |                        |
+----------------------------------------+----------------------------------------+------------------------------------------------------------------+---------------------------------+------------------------+
| container_map:base_image               | container_map.base_image               | Base image to use for attached volumes.                          | ``tianon/true:latest``          |                        |
+----------------------------------------+----------------------------------------+------------------------------------------------------------------+---------------------------------+------------------------+
| container_map:core_image               | container_map.core_image               | Core image for initializing attached volumes' permissions.       | ``busybox:latest``              |                        |
+----------------------------------------+----------------------------------------+------------------------------------------------------------------+---------------------------------+------------------------+
