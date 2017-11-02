# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import

from dockermap.map.yaml import yaml
from msgpack import ExtType
from salt.utils.yamlloader import SaltYamlSafeLoader

_ext_types = {}


def render(yaml_data, saltenv='base', sls='', **kws):
    config_get = __salt__['config.get']
    _ext_types['pillar'] = config_get('lazy_yaml.ext_code_pillar', 10)
    _ext_types['grain'] = config_get('lazy_yaml.ext_code_grain', 11)
    if config_get('lazy_yaml.skip_render', False):
        return yaml_data

    if not isinstance(yaml_data, basestring):
        yaml_data = yaml_data.read()
    data = yaml.load(yaml_data, Loader=SaltYamlSafeLoader)
    return data if data else {}


def expand_pillar_lazy(loader, node):
    """
    Substitutes a variable read from a YAML node with a MsgPack ExtType value referring to data stored in a pillar.

    :param loader: YAML loader.
    :type loader: yaml.loader.SafeLoader
    :param node: Document node.
    :type node: ScalarNode
    :return: Corresponding value stored in the pillar.
    :rtype: msgpack.ExtType
    """
    val = loader.construct_scalar(node)
    return ExtType(_ext_types['pillar'], val.encode('utf-8'))


def expand_grain_lazy(loader, node):
    """
    Substitutes a variable read from a YAML node with a MsgPack ExtType value referring to data stored in a grain.

    :param loader: YAML loader.
    :type loader: yaml.loader.SafeLoader
    :param node: Document node.
    :type node: ScalarNode
    :return: Corresponding value stored in the grain.
    :rtype: msgpack.ExtType
    """
    val = loader.construct_scalar(node)
    return ExtType(_ext_types['grain'], val.encode('utf-8'))


yaml.add_constructor('!pillar', expand_pillar_lazy, SaltYamlSafeLoader)
yaml.add_constructor('!grain', expand_grain_lazy, SaltYamlSafeLoader)
