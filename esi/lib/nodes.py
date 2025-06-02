#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

import concurrent.futures
import warnings
import json

from openstack import exceptions
from keystoneauth1.exceptions.http import HttpError

from esi.lib import networks


OPENSTACK_IRONIC_API_VERSION = "1.69"


def node_and_port_list(connection, filter_node=None):
    """Get lists baremetal nodes and ports

    :param connection: An OpenStack connection
    :type connection: :class:`~openstack.connection.Connection`
    :param filter_node: The name or ID of a node

    :returns: A tuple of lists of nodes and ports of the form:
    (
        [openstack.baremetal.v1.node.Node],
        [openstack.baremetal.v1.port.Port]
    )
    """

    nodes = None
    ports = None

    if filter_node:
        nodes = [
            connection.baremetal.find_node(name_or_id=filter_node, ignore_missing=False)
        ]
        ports = connection.baremetal.ports(details=True, node_id=nodes[0].id)
    else:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            f1 = executor.submit(connection.baremetal.nodes)
            f2 = executor.submit(connection.baremetal.ports, details=True)
            nodes = list(f1.result())
            ports = list(f2.result())

    return nodes, ports


def network_list(connection, filter_node=None, filter_network=None):
    """List nodes and their network attributes

    :param connection: An OpenStack connection
    :type connection: :class:`~openstack.connection.Connection`
    :param filter_node: the name or ID of a node
    :param filter_network: The name or ID of a network

    :returns: A list of dictionaries of the form:
    {
        'node': openstack.baremetal.v1.node.Node,
        'network_info': [
            {
                'baremetal_port': openstack.baremetal.v1.port.Port,
                'network_ports': [openstack.network.v2.port.Port] or [],
                'networks': {
                    'parent': openstack.network.v2.network.Network or None,
                    'trunk': [openstack.network.v2.network.Network] or [],
                    'floating': openstack.network.v2.network.Network or None,
                },
                'floating_ip': openstack.network.v2.floating_ip.FloatingIP or None,
                'port_forwardings': [openstack.network.v2.port_forwarding.PortForwarding] or []
            },
            ...
        ]
    }
    """

    with concurrent.futures.ThreadPoolExecutor() as executor:
        f1 = executor.submit(node_and_port_list, connection, filter_node)
        if filter_network:
            f3 = executor.submit(
                connection.network.find_network,
                name_or_id=filter_network,
                ignore_missing=False,
            )
            filter_network = f3.result()
        f2 = executor.submit(networks.network_and_port_list, connection, filter_network)
        baremetal_nodes, baremetal_ports = f1.result()
        network_ports_dict, networks_dict, floating_ips_dict, port_forwardings_dict = (
            f2.result()
        )

    data = []
    for baremetal_node in baremetal_nodes:
        network_info = []
        node_ports = [bp for bp in baremetal_ports if bp.node_id == baremetal_node.id]

        for baremetal_port in node_ports:
            network_port = None
            network_port_id = baremetal_port.internal_info.get(
                "tenant_vif_port_id", None
            )

            if network_port_id:
                network_port = network_ports_dict.get(network_port_id)

            if network_port is not None and (
                not filter_network or filter_network.id == network_port.network_id
            ):
                parent_network, trunk_networks, trunk_ports, floating_network = (
                    networks.get_networks_from_port(
                        connection,
                        network_port,
                        networks_dict,
                        network_ports_dict,
                        floating_ips_dict,
                    )
                )

                network_info.append(
                    {
                        "baremetal_port": baremetal_port,
                        "network_ports": [network_port] + trunk_ports,
                        "networks": {
                            "parent": parent_network,
                            "trunk": trunk_networks,
                            "floating": floating_network,
                        },
                        "floating_ip": floating_ips_dict.get(network_port.id, None),
                        "port_forwardings": port_forwardings_dict.get(
                            network_port.id, []
                        ),
                    }
                )
            elif not filter_network:
                network_info.append(
                    {
                        "baremetal_port": baremetal_port,
                        "network_ports": [],
                        "networks": {"parent": None, "trunk": [], "floating": None},
                        "floating_ip": None,
                        "port_forwardings": [],
                    }
                )

        if network_info != []:
            data.append({"node": baremetal_node, "network_info": network_info})

    return data


def network_attach(connection, node, attach_info):
    """Attaches a node's bare metal port to a network port

    :param connection: An OpenStack connection
    :type connection: :class:`~openstack.connection.Connection`
    :param node: The name or ID of a node
    :param attach_info: A dictionary. Possible entrys are:
        * 'network': <network name or ID>
        * 'port': <port name or ID> (The network port to attach)
        * 'trunk': <trunk name or ID>
        * 'mac_address': <MAC addresses> (The MAC address of the bare metal port to attach)

    :returns: a dictionary with the resulting node and network information
    {
        'node': openstack.baremetal.v1.node.Node,
        'ports': [openstack.network.v2.port.Port]
        'networks': [openstack.network.v2.network.Network]
    }
    """

    network = attach_info.get("network")
    port = attach_info.get("port")
    trunk = attach_info.get("trunk")
    mac_address = attach_info.get("mac_address")

    if (network and port) or (network and trunk) or (port and trunk):
        raise exceptions.InvalidRequest("Specify only one of network, port, or trunk")
    if not network and not port and not trunk:
        raise exceptions.InvalidRequest(
            "You must specify either network, port, or trunk"
        )

    if network:
        parent_network = connection.network.find_network(network, ignore_missing=False)
        network_port = None
    elif port:
        network_port = connection.network.find_port(port, ignore_missing=False)
    elif trunk:
        trunk_network = connection.network.find_trunk(trunk, ignore_missing=False)
        network_port = None

    with concurrent.futures.ThreadPoolExecutor() as executor:
        f1 = executor.submit(connection.baremetal.get_node, node)
        f2 = executor.submit(
            connection.session.get_endpoint,
            service_type="baremetal",
            service_name="ironic",
            interface="public",
        )
        node = f1.result()
        baremetal_endpoint = f2.result()

    if mac_address:
        baremetal_ports = list(
            connection.baremetal.ports(details=True, address=mac_address)
        )
        if len(baremetal_ports) == 0:
            raise exceptions.ResourceFailure(
                "MAC address {0} does not exist on node {1}".format(
                    mac_address, node.name
                )
            )
    else:
        baremetal_ports = connection.baremetal.ports(details=True, node=node.id)
        has_free_port = False
        for bp in baremetal_ports:
            if "tenant_vif_port_id" not in bp.internal_info:
                has_free_port = True
                break

        if not has_free_port:
            raise exceptions.ResourceFailure(
                "Node {0} has no free ports".format(node.name)
            )

    if network:
        network_port = networks.create_port(connection, node.name, parent_network)
    elif trunk:
        network_port = connection.network.find_port(
            trunk_network.port_id, ignore_missing=False
        )

    data = {"id": network_port.id}
    if mac_address:
        data["port_uuid"] = baremetal_ports[0].id

    # TODO(ajamias) There should be a function in openstacksdk that specifies
    # a bare metal port's MAC address to attach a network port to

    try:
        connection.session.post(
            f"{baremetal_endpoint}/v1/nodes/{node.id}/vifs",
            headers={"X-OpenStack-Ironic-API-Version": OPENSTACK_IRONIC_API_VERSION},
            json=data,
        )
    except HttpError as e:
        body = e.response.json()
        message = json.loads(body.get("error_message", "{}")).get("faultstring", str(e))
        raise exceptions.ResourceFailure(message)

    network_port = connection.network.find_port(network_port.id, ignore_missing=False)

    networks_dict = {}
    if network:
        networks_dict[parent_network.id] = parent_network
    elif trunk:
        networks_dict[trunk_network.id] = trunk_network
    parent_network, trunk_networks, trunk_ports, _ = networks.get_networks_from_port(
        connection, network_port, networks_dict=networks_dict
    )

    return {
        "node": node,
        "ports": [network_port] + trunk_ports,
        "networks": [parent_network] + trunk_networks,
    }


def network_detach(
    connection, node_name_or_uuid, port=None, port_names_or_uuids=None, all_ports=False
):
    """Detaches a node's bare metal port from a network port

    :param port: The name or ID of a network port

    :returns: A list of ``(port_uuid, bool)`` tuples, where ``bool`` is ``True`` if the port was removed
    successfully, ``False`` otherwise.
    """

    if port and port_names_or_uuids:
        raise ValueError("do not set both port and port_names_or_uuids")

    if (port or port_names_or_uuids) and all_ports:
        raise ValueError("do not specify individual ports with all_ports=true")

    if port:
        port_names_or_uuids = [port]
        warnings.warn(
            "The 'port' parameter is deprecated and will be removed in a future release.",
            DeprecationWarning,
            stacklevel=2,
        )

    node = connection.baremetal.get_node(node_name_or_uuid)
    ports = []
    if port_names_or_uuids:
        ports = [
            connection.network.find_port(port, ignore_missing=False)
            for port in port_names_or_uuids
        ]
    else:
        bm_ports = connection.baremetal.ports(details=True, node=node.id)

        mapped_node_port_list = [
            bm_port
            for bm_port in bm_ports
            if bm_port.internal_info.get("tenant_vif_port_id")
        ]

        if len(mapped_node_port_list) == 0:
            raise exceptions.ResourceFailure(
                "Node {0} is not associated with any port".format(node.name)
            )

        if all_ports:
            ports = [
                connection.network.find_port(
                    bmport.internal_info["tenant_vif_port_id"], ignore_missing=False
                )
                for bmport in mapped_node_port_list
            ]
        elif len(mapped_node_port_list) > 1:
            raise exceptions.ResourceFailure(
                "Node {0} is associated with multiple ports. Port must be specified".format(
                    node.name
                )
            )
        elif len(mapped_node_port_list) == 1:
            vif = mapped_node_port_list[0].internal_info["tenant_vif_port_id"]
            port = connection.network.find_port(vif, ignore_missing=False)
            ports = [port]

    return [
        (port.id, connection.baremetal.detach_vif_from_node(node, port.id))
        for port in ports
    ]
