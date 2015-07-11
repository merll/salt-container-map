# -*- coding: utf-8 -*-
import argparse
from collections import namedtuple
import logging
import os

import salt.config


log = logging.getLogger()

InstallEnvironment = namedtuple('InstallEnvironment', ['lib_path', 'salt_config', 'salt_extmods', 'salt_root'])


def _expand_path(root, path):
    if os.path.isabs(path):
        return path
    return os.path.join(root, path)


def _read_extmods(master_opts):
    root_dir = master_opts.get('root_dir')
    ext_mods = master_opts.get('extension_modules')
    if ext_mods:
        log.debug("Using extension_modules from master config: %s", ext_mods)
        return _expand_path(root_dir, ext_mods)
    module_dirs = master_opts.get('module_dirs')
    if module_dirs:
        log.debug("Using first module_dirs from master config: %s", module_dirs[0])
        return _expand_path(root_dir, module_dirs[0])
    return None


def _read_root(master_opts):
    fs_base = master_opts.get('file_roots', {}).get('base')
    if fs_base:
        log.debug("Using salt filesystem base root from master config: %s", fs_base[0])
        return fs_base[0]
    return None


def link_module(salt_path, lib_dir, sub_dir, file_name):
    module_path = os.path.join(lib_dir, file_name)
    link_dir = os.path.join(salt_path, sub_dir)
    log.debug("setting up module in %s", link_dir)
    link_path = os.path.join(link_dir, file_name)
    init_path = os.path.join(link_dir, '__init__.py')
    if not os.path.isdir(link_dir):
        log.info("creating symlink %s -> %s", link_path, module_path)
        os.mkdir(link_dir)
        open(init_path, 'a').close()
        os.symlink(module_path, link_path)
        return True

    if os.path.lexists(link_path):
        if os.path.islink(link_path):
            link_target = os.readlink(link_path)
            if link_target != module_path:
                log.warning("File %s exists, but is not a symlink pointing to %s.", link_path, module_path)
            else:
                log.info("Found existing symlink.")
        else:
            log.warning("File %s exists, but is not a symbolic link.", link_path)
        return False

    log.info("creating symlink %s -> %s", link_path, module_path)
    if not os.path.exists(init_path):
        open(init_path, 'a').close()
    os.symlink(module_path, link_path)
    return True


def unlink_module(salt_path, sub_dir, file_name):
    link_dir = os.path.join(salt_path, sub_dir)
    log.info("removing module from %s", link_dir)
    link_path = os.path.join(link_dir, file_name)
    if os.path.islink(link_path):
        os.unlink(link_path)
        return True
    return False


def get_env():
    parser = argparse.ArgumentParser(description="Installs symlinks to the modules in the Salt module directories.")
    parser.add_argument('-c', '--salt-config', default='/etc/salt/master',
                        help="Path to the salt master configuration file.")
    parser.add_argument('--salt-extmods', help="Path for extension modules. If not set, the setting from the master "
                                               "config is used.")
    parser.add_argument('--salt-root', help="Path to the master file root, e.g. /srv/salt. If not set, looks up the "
                                            "base environment in the master configuration file.")
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument('-v', '--verbose', action='store_true', help="Show debug messages.")
    output_group.add_argument('-q', '--quiet', action='store_true', help="Do not show any messages.")

    args = parser.parse_args()
    if not args.quiet:
        ch = logging.StreamHandler()
        formatter = logging.Formatter('%(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        log.addHandler(ch)
        if args.verbose:
            log.setLevel(logging.DEBUG)
        else:
            log.setLevel(logging.INFO)

    salt_config = args.salt_config
    master_opts = salt.config.master_config(salt_config)
    if args.salt_extmods:
        salt_extmods = args.salt_extmods
    else:
        salt_extmods = _read_extmods(master_opts)
    if args.salt_root:
        salt_root = args.salt_root
    else:
        salt_root = _read_root(master_opts)

    if not os.path.isdir(salt_extmods):
        log.error("Extension module directory %s does not exist.", salt_extmods)
        parser.exit(status=1)
    if not os.path.isdir(salt_root):
        log.error("Master file root directory %s does not exist.", salt_root)
        parser.exit(status=1)

    return InstallEnvironment(os.path.dirname(__file__), salt_config, salt_extmods, salt_root)


def install_modules():
    env = get_env()
    res_extmod = link_module(env.salt_extmods, os.path.join(env.lib_path, 'extmods'), 'renderers', 'lazy_yaml.py')
    res_mod = link_module(env.salt_root, os.path.join(env.lib_path, 'modules'), '_modules', 'container_map.py')
    res_state = link_module(env.salt_root, os.path.join(env.lib_path, 'states'), '_states', 'container_map.py')
    if res_extmod:
        log.info("Installed master extension module. Please restart the salt master process for using it.")
    if res_mod and res_state:
        log.info("Installed minion modules. Distribute with 'saltutil.sync_all' or 'state.highstate'.")


def remove_modules():
    env = get_env()
    res_extmod = unlink_module(env.salt_extmods, 'renderers', 'lazy_yaml.py')
    res_mod = unlink_module(env.salt_root, '_modules', 'container_map.py')
    res_state = unlink_module(env.salt_root, '_states', 'container_map.py')
    if res_extmod:
        log.info("Removed master extension module. It will not be available after the master process is restarted.")
    if res_mod and res_state:
        log.info("Removed minion modules. 'saltutil.clear_cache' can be used for distributing the removal, but "
                 "'saltutil.sync_all' should be run immediately afterwards if you have any other custom modules.")
