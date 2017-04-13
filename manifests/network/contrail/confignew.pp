#
# Copyright (C) 2015 Juniper Networks
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# == Class: tripleo::network::contrail::config
#
# Configure Contrail Config services
#
# == Parameters:
#
#
# [*aaa_mode*]
#  (optional) aaa mode parameter
#  String value.
#  Defaults to hiera('contrail::aaa_mode')
#
# [*admin_password*]
#  (optional) admin password
#  String value.
#  Defaults to hiera('contrail::admin_password')
#
# [*admin_tenant_name*]
#  (optional) admin tenant name.
#  String value.
#  Defaults to hiera('contrail::admin_tenant_name')
#
# [*admin_token*]
#  (optional) admin token
#  String value.
#  Defaults to hiera('contrail::admin_token')
#
# [*admin_user*]
#  (optional) admin user name.
#  String value.
#  Defaults to hiera('contrail::admin_user')
#
# [*api_server*]
#  (optional) VIP of Config API
#  String (IPv4) value.
#  Defaults to hiera('internal_api_virtual_ip')
#  
#  [*api_server_new*]
#  (optional) IP of the new CFGM node (ISSU case)
#
# [*api_port*]
#  (optional) Port of Config API
#  String value.
#  Defaults to hiera('contrail::api_port')
#
# [*auth*]
#  (optional) Authentication method.
#  Defaults to hiera('contrail::auth')
#
# [*auth_host*]
#  (optional) keystone server ip address
#  String (IPv4) value.
#  Defaults to hiera('contrail::auth_host')
#
# [*auth_port*]
#  (optional) keystone port.
#  Defaults to hiera('contrail::auth_port')
#
# [*auth_port_ssl*]
#  (optional) keystone ssl port.
#  Integer value.
#  Defaults to hiera('contrail::auth_port_ssl')
#
# [*auth_protocol*]
#  (optional) authentication protocol.
#  Defaults to hiera('contrail::auth_protocol')
#
# [*ca_file*]
#  (optional) ca file name
#  String value.
#  Defaults to hiera('contrail::service_certificate',false)
#
# [*cert_file*]
#  (optional) cert file name
#  String value.
#  Defaults to hiera('contrail::service_certificate',false)
#
# [*cassandra_server_list*]
#  (optional) List IPs+port of Cassandra servers
#  Array of strings value.
#  Defaults to hiera('contrail::cassandra_server_list')
#
# [*config_hostnames*]
#  (optional) Config hostname list
#  Array of string value.
#  Defaults to hiera('contrail_config_short_node_names')
#
# [*control_server_list*]
#  (optional) IPv4 addresses of control server.
#  Array of string (IPv4) value.
#  Defaults to hiera('contrail_control_node_ips')
#
# [*disc_server_ip*]
#  (optional) IPv4 address of discovery server.
#  String (IPv4) value.
#  Defaults to hiera('contrail::disc_server_ip')
#
# [*disc_server_port*]
#  (optional) port of discovery server
#  String value.
#  Defaults to hiera('contrail::disc_server_port')
#
# [*host_ip*]
#  (optional) IPv4 address of Config server
#  String (IPv4) value.
#  Defaults to hiera('contrail::config::host_ip')
#
# [*ifmap_password*]
#  (optional) ifmap password
#  String value.
#  Defaults to hiera('contrail::config::ifmap_password')
#
# [*ifmap_server_ip*]
#  (optional) ifmap server ip address.
#  String value.
#  Defaults to hiera('contrail::config::host_ip')
#
# [*ifmap_username*]
#  (optional) ifmap username
#  String value.
#  Defaults to hiera('contrail::config::ifmap_password')
#
# [*insecure*]
#  (optional) insecure mode.
#  Defaults to hiera('contrail::insecure')
#
# [*ipfabric_service_port*]
#  (optional) linklocal ip fabric port
#  String value
#  Defaults to 8775
#
# [*listen_ip_address*]
#  (optional) IP address to listen on.
#  String (IPv4) value.
#  Defaults to hiera('contrail::config::listen_ip_address')
#
# [*listen_port*]
#  (optional) Listen port for config-api
#  Defaults to hiera('contrail::api_port')
#
# [*linklocal_service_name*]
#  (optional) name of link local service
#  String value
#  Defaults to metadata
#
# [*linklocal_service_port*]
#  (optional) port of link local service
#  String value
#  Defaults to 80
#
# [*linklocal_service_name*]
#  (optional) name of link local service
#  String value
#  Defaults to metadata
#
# [*linklocal_service_ip*]
#  (optional) IPv4 address of link local service
#  String (IPv4) value
#  Defaults to 169.254.169.254
#
# [*memcached_servers*]
#  (optional) IPv4 address of memcached servers
#  String (IPv4) value + port
#  Defaults to hiera('contrail::memcached_server')
#
# [*public_vip*]
#  (optional) Public virtual ip
#  String value.
#  Defaults to hiera('public_virtual_ip')
#
# [*step*]
#  (optional) Step stack is in
#  Integer value.
#  Defaults to hiera('step')
#
# [*rabbit_server*]
#  (optional) rabbit server
#  Array of string value.
#  Defaults to hiera('rabbitmq_node_ips')
#
# [*rabbit_user*]
#  (optional) rabbit user
#  String value.
#  Defaults to hiera('contrail::rabbit_user')
#
# [*rabbit_password*]
#  (optional) rabbit password
#  String value.
#  Defaults to hiera('contrail::rabbit_password')
#
# [*rabbit_port*]
#  (optional) rabbit server port
#  String value.
#  Defaults to hiera('contrail::rabbit_port')
#
# [*redis_server*]
#  (optional) IPv4 address of redis server.
#  String (IPv4) value.
#  Defaults to hiera('contrail::config::redis_server')
#
# [*zk_server_ip*]
#  (optional) List IPs+port of Zookeeper servers
#  Array of strings value.
#  Defaults to hiera('contrail_database_node_ips')
#
class tripleo::network::contrail::confignew(
  $step  = hiera('step'),
  $aaa_mode               = hiera('contrail::aaa_mode'),
  $admin_password         = hiera('contrail::admin_password'),
  $admin_tenant_name      = hiera('contrail::admin_tenant_name'),
  $admin_token            = hiera('contrail::admin_token'),
  $admin_user             = hiera('contrail::admin_user'),
  $analytics_list         = hiera('contrail_analytics_new_node_ips'),
  $analytics_names        = hiera('contrail_analytics_new_short_node_names'),
  $api_server_new_list    = hiera('contrail_config_new_node_ips'), # We should attach to  any of the new CFGM nodes
  $api_port               = hiera('contrail::api_port'),
  $auth                   = hiera('contrail::auth'),
  $auth_host              = hiera('contrail::auth_host'),
  $auth_port              = hiera('contrail::auth_port'),
  $auth_port_ssl          = hiera('contrail::auth_port_ssl'),
  $auth_protocol          = hiera('contrail::auth_protocol'),
  $cassandra_hostnames    = hiera('contrail_database_new_short_node_names'),
  $cassandra_server_list  = hiera('contrail_database_new_node_ips'),
  $ca_file                = hiera('contrail::service_certificate',false),
  $cassandra_port         = 9160,
  $cert_file              = hiera('contrail::service_certificate',false),
  $config_hostnames       = hiera('contrail_config_new_short_node_names'),
  $control_hostnames      = hiera('contrail_control_new_short_node_names'),
  $control_server_list    = hiera('contrail_control_new_node_ips'),
  $disc_server_ip_list    = hiera('contrail_config_new_node_ips'),
  $disc_server_port       = hiera('contrail::disc_server_port'),
  $host_ip                = hiera('contrail::confignew::host_ip'),
  $ifmap_password         = hiera('contrail::confignew::ifmap_password'),
  $ifmap_server_ip        = hiera('contrail::confignew::host_ip'),
  $ifmap_username         = hiera('contrail::confignew::ifmap_username'),
  $insecure               = hiera('contrail::insecure'),
  $ipfabric_service_port  = 8775,
  $listen_ip_address      = hiera('contrail::confignew::listen_ip_address'),
  $listen_port            = hiera('contrail::api_port'),
  $linklocal_service_port = 80,
  $linklocal_service_name = 'metadata',
  $linklocal_service_ip   = '169.254.169.254',
  $memcached_servers      = hiera('contrail::memcached_server'),
  $old_db_servers         = hiera('contrail_config_node_ips'),
  $old_zk_servers         = hiera('contrail_config_node_ips'),
  $old_zk_port            = 2181,
  $old_rabbit_servers     = hiera('rabbitmq_node_ips'),
  $old_rabbit_vhost       = '/',
  $old_control_list       = hiera('contrail_control_node_ips'),
  $old_control_names      = hiera('contrail_control_short_node_names'),
  $public_vip             = hiera('public_virtual_ip'),
  $rabbit_server          = hiera('rabbitmq_node_ips'),
  $rabbit_user            = hiera('contrail::rabbit_user'),
  $rabbit_password        = hiera('contrail::rabbit_password'),
  $rabbit_port            = hiera('contrail::rabbit_port'),
  $rabbit_vhost           = '/new',
  $redis_server           = hiera('contrail::confignew::redis_server'),
  $zk_port                = 2181,
  $zk_server_ip           = hiera('contrail_database_new_node_ips'),
)
{
  $api_server_new = $api_server_new_list[0]
  $disc_server_ip =   $disc_server_ip_list[0]
  validate_ip_address($listen_ip_address)
  validate_ip_address($disc_server_ip)
  validate_ip_address($ifmap_server_ip)
  $basicauthusers_property_control = map($control_server_list) |$item| { "${item}.control:${item}.control" }
  $basicauthusers_property_dns = $control_server_list.map |$item| { "${item}.dns:${item}.dns" }
  $basicauthusers_property = concat($basicauthusers_property_control, $basicauthusers_property_dns)
  $cassandra_server_list_9160 = join([join($cassandra_server_list, ':9160 '),':9160'],'')
  $rabbit_server_list_5672 = join([join($rabbit_server, ':5672,'),':5672'],'')
  $zk_server_ip_2181 = join([join($zk_server_ip, ':2181,'),':2181'],'')

  $old_db_servers_str = join($old_db_servers,",")
  $old_zk_servers_str = join($old_db_servers,",")
  $old_rabbit_servers_str = join($old_rabbit_servers,",")
  $old_control_list_str = join($old_control_list,",")
  $cassandra_server_list_str = join($cassandra_server_list,",")
  $zk_server_ip_str = join($zk_server_ip,",")
  $rabbit_server_str = join($rabbit_server,",")
  $control_server_list_str = join($control_server_list,",")

  $config_old_quotes = map($old_control_list) |$item| {"'$item'" }
  $config_old_name_quotes = map($old_control_names) |$item| {"'$item'" }
  $config_old_hash = zip($config_old_quotes, $config_old_name_quotes)
  $config_old_info_str = inline_template('<%= @config_old_hash.to_s %>')
  $config_old_info_str1 = regsubst(regsubst(regsubst(regsubst(regsubst($config_old_info_str, '", ', '":', 'G'), '"', '', 'G'), '\[', '', 'G'), '\]', '', 'G'), ', ', ',', 'G')
  $config_old_info = "{$config_old_info_str1}"

  $config_new_quotes = map($control_server_list) |$item| {"'$item'" }
  $config_new_name_quotes = map($control_hostnames) |$item| {"'$item'" }
  $config_new_hash = zip($config_new_quotes, $config_new_name_quotes)
  $config_new_info_str = inline_template('<%= @config_new_hash.to_s %>')
  $config_new_info_str1 = regsubst(regsubst(regsubst(regsubst(regsubst($config_new_info_str, '", ', '":', 'G'), '"', '', 'G'), '\[', '', 'G'), '\]', '', 'G'), ', ', ',', 'G')
  $config_new_info = "{$config_new_info_str1}"

  $cassandra_new_quotes = map($cassandra_server_list) |$item| {"'$item'" }
  $cassandra_new_name_quotes = map($cassandra_hostnames) |$item| {"'$item'" }
  $cassandra_new_hash = zip($cassandra_new_quotes, $cassandra_new_name_quotes)
  $cassandra_new_info_str = inline_template('<%= @cassandra_new_hash.to_s %>')
  $cassandra_new_info_str1 = regsubst(regsubst(regsubst(regsubst(regsubst($cassandra_new_info_str, '", ', '":', 'G'), '"', '', 'G'), '\[', '', 'G'), '\]', '', 'G'), ', ', ',', 'G')
  $cassandra_new_info = "{$cassandra_new_info_str1}"

  $analytics_new_quotes = map($analytics_list) |$item| {"'$item'" }
  $analytics_new_name_quotes = map($analytics_names) |$item| {"'$item'" }
  $analytics_new_hash = zip($analytics_new_quotes, $analytics_new_name_quotes)
  $analytics_new_info_str = inline_template('<%= @analytics_new_hash.to_s %>')
  $analytics_new_info_str1 = regsubst(regsubst(regsubst(regsubst(regsubst($analytics_new_info_str, '", ', '":', 'G'), '"', '', 'G'), '\[', '', 'G'), '\]', '', 'G'), ', ', ',', 'G')
  $analytics_new_info = "{$analytics_new_info_str1}"

  $my_string_1 = inline_template('<%= @api_server_new_list.to_s %>')
  $my_string_2 = regsubst(regsubst($my_string_1, '\[', '{', 'G'), '\]', ':[\'root\',\'XXXX\']}')
  $my_string_3 = regsubst($my_string_2, '"', '\'', 'G')
  $api_info = regsubst($my_string_3, ', ', ':[\'root\',\'XXXX\'],', 'G')

  if $auth_protocol == 'https' {
    $keystone_config = {
      'KEYSTONE' => {
        'admin_password'    => $admin_password,
        'admin_tenant_name' => $admin_tenant_name,
        'admin_token'       => $admin_token,
        'admin_user'        => $admin_user,
        'auth_host'         => $auth_host,
        'auth_port'         => $auth_port_ssl,
        'auth_protocol'     => $auth_protocol,
        'insecure'          => $insecure,
        'memcached_servers' => $memcached_servers,
        'certfile'          => $cert_file,
        'cafile'            => $ca_file,
      },
    }
    $vnc_api_lib_config = {
      'auth' => {
        'AUTHN_SERVER'   => $public_vip,
        'AUTHN_PORT'     => $auth_port_ssl,
        'AUTHN_PROTOCOL' => $auth_protocol,
        'certfile'       => $cert_file,
        'cafile'         => $ca_file,
      },
    }
  } else {
    $keystone_config = {
      'KEYSTONE' => {
        'admin_password'    => $admin_password,
        'admin_tenant_name' => $admin_tenant_name,
        'admin_token'       => $admin_token,
        'admin_user'        => $admin_user,
        'auth_host'         => $auth_host,
        'auth_port'         => $auth_port,
        'auth_protocol'     => $auth_protocol,
        'insecure'          => $insecure,
        'memcached_servers' => $memcached_servers,
      },
    }
    $vnc_api_lib_config = {
      'auth' => {
        'AUTHN_SERVER' => $public_vip,
      },
    }
  }
  if $step >= 3 {
    class {'::contrail::confignew':
      api_config              => {
        'DEFAULTS' => {
          'aaa_mode'              => $aaa_mode,
          'auth'                  => $auth,
          'cassandra_server_list' => $cassandra_server_list_9160,
          'disc_server_ip'        => $disc_server_ip,
          'ifmap_password'        => $ifmap_password,
          'ifmap_server_ip'       => $ifmap_server_ip,
          'ifmap_username'        => $ifmap_username,
          'listen_ip_addr'        => $listen_ip_address,
          'listen_port'           => $listen_port,
          'rabbit_server'         => $rabbit_server_list_5672,
          'rabbit_user'           => $rabbit_user,
          'rabbit_password'       => $rabbit_password,
          'redis_server'          => $redis_server,
          'rabbit_vhost'          => $rabbit_vhost,
          'zk_server_ip'          => $zk_server_ip_2181,
        },
      },
      basicauthusers_property => $basicauthusers_property,
      config_nodemgr_config   => {
        'DISCOVERY' => {
          'server' => $disc_server_ip,
          'port'   => $disc_server_port,
        },
      },
      contrail_issu_config    => {
        'DEFAULTS' => {
          'old_cassandra_address_list'    => $old_db_servers_str,
          'old_zookeeper_address_list'    => $old_db_servers_str,
          'old_zookeeper_port'            => $old_zk_port,
          'old_rabbit_port'               => $rabbit_port,
          'old_rabbit_address_list'       => $old_rabbit_servers_str,
          'old_rabbit_vhost'              => $old_rabbit_vhost,
          'old_rabbit_user'               => $rabbit_user,
          'old_rabbit_password'           => $rabbit_password,
          'old_control_list'              => $old_control_list_str,
          'old_control_host_info'         => $config_old_info,
          'new_cassandra_address_list'    => $cassandra_server_list_str,
          'new_cassandra_port'            => $cassandra_port,
          'new_zookeeper_address_list'    => $zk_server_ip_str,
          'new_zookeeper_port'            => $zk_port,
          'new_rabbit_address_list'       => $rabbit_server_str,
          'new_rabbit_port'               => $rabbit_port,
          'new_rabbit_user'               => $rabbit_user,
          'new_rabbit_password'           => $rabbit_password,
          'new_control_list'              => $control_server_list_str,
          'new_api_info'                  => $api_info,
          'db_host_info'                  => $cassandra_new_info,
          'config_host_info'              => $config_new_info,
          'analytics_host_info'           => $analytics_new_info,
          'control_host_info'             => $config_new_info,
          'admin_password'                => $admin_password,
          'admin_user'                    => $admin_user,
          'admin_tenant_name'             => $admin_tenant_name,
          'openstack_ip'                  => $auth_host,
          'new_rabbit_vhost'              => $rabbit_vhost,
        },
      },
      device_manager_config   => {
        'DEFAULTS' => {
          'api_server_ip'         => $api_server_new,
          'api_server_port'       => $api_port,
          'cassandra_server_list' => $cassandra_server_list_9160,
          'disc_server_ip'        => $disc_server_ip,
          'disc_server_port'      => $disc_server_port,
          'rabbit_server'         => $rabbit_server_list_5672,
          'rabbit_user'           => $rabbit_user,
          'rabbit_password'       => $rabbit_password,
          'rabbit_vhost'          => $rabbit_vhost,
          'redis_server'          => $redis_server,
          'zk_server_ip'          => $zk_server_ip_2181,
        },
      },
      discovery_config        => {
        'DEFAULTS' => {
          'cassandra_server_list' => $cassandra_server_list_9160,
          'zk_server_ip'          => $zk_server_ip_2181,
          },
      },
      keystone_config         => $keystone_config,
      schema_config           => {
        'DEFAULTS' => {
          'api_server_ip'         => $api_server_new,
          'api_server_port'       => $api_port,
          'cassandra_server_list' => $cassandra_server_list_9160,
          'disc_server_ip'        => $disc_server_ip,
          'disc_server_port'      => $disc_server_port,
          'ifmap_password'        => $ifmap_password,
          'ifmap_server_ip'       => $ifmap_server_ip,
          'ifmap_username'        => $ifmap_username,
          'rabbit_server'         => $rabbit_server_list_5672,
          'rabbit_user'           => $rabbit_user,
          'rabbit_password'       => $rabbit_password,
          'rabbit_vhost'          => $rabbit_vhost,
          'redis_server'          => $redis_server,
          'zk_server_ip'          => $zk_server_ip_2181,
        },
      },
      svc_monitor_config      => {
        'DEFAULTS' => {
          'api_server_ip'         => $api_server_new,
          'api_server_port'       => $api_port,
          'cassandra_server_list' => $cassandra_server_list_9160,
          'disc_server_ip'        => $disc_server_ip,
          'disc_server_port'      => $disc_server_port,
          'ifmap_password'        => $ifmap_password,
          'ifmap_server_ip'       => $ifmap_server_ip,
          'ifmap_username'        => $ifmap_username,
          'rabbit_server'         => $rabbit_server_list_5672,
          'rabbit_user'           => $rabbit_user,
          'rabbit_password'       => $rabbit_password,
          'rabbit_vhost'          => $rabbit_vhost,
          'redis_server'          => $redis_server,
          'zk_server_ip'          => $zk_server_ip_2181,
        },
      },
      vnc_api_lib_config      => $vnc_api_lib_config,
    }
  }
  if $step >= 5 {
    class {'::contrail::confignew::provision_config':
      api_address                => $api_server_new,
      api_port                   => $api_port,
      config_node_address        => $host_ip,
      config_node_name           => $::hostname,
      keystone_admin_user        => $admin_user,
      keystone_admin_password    => $admin_password,
      keystone_admin_tenant_name => $admin_tenant_name,
      openstack_vip              => $public_vip,
    }
    if $config_hostnames[0] == $::hostname {
      class {'::contrail::confignew::provision_linklocal':
        api_address                => $api_server_new,
        api_port                   => $api_port,
        ipfabric_service_ip        => $api_server_new,
        ipfabric_service_port      => $ipfabric_service_port,
        keystone_admin_user        => $admin_user,
        keystone_admin_password    => $admin_password,
        keystone_admin_tenant_name => $admin_tenant_name,
        linklocal_service_name     => $linklocal_service_name,
        linklocal_service_ip       => $linklocal_service_ip,
        linklocal_service_port     => $linklocal_service_port,
      }
    }
  }
}
