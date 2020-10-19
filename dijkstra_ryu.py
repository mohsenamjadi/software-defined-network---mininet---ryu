# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
from collections import defaultdict
import logging

# switches
switches = []
# mymac[srcmac]->(switch, port)
mymac = {}
# adjacency map [sw1][sw2]->port from sw1 to sw2
adjacency = defaultdict(lambda: defaultdict(lambda: None))

# GETS Q AS ARGUMENTS AND RETURNS THE NODE WITH MINIMUM DISTANCE
def minimum_distance(distance, Q):
    min = float('Inf')
    node = 0
    for v in Q:
        if distance[v] < min:
            min = distance[v]
            node = v
    return node

#by considering first port and final port this function gets the path for source to destination
def get_path(src, dst, first_port, final_port):
    # Dijkstra's algorithm
    print("get_path is called, src=", src, " dst=", dst, " first_port=", first_port, " final_port=", final_port)
    logger.debug("get_path is called, src=", src, " dst=", dst, " first_port=", first_port, " final_port=", final_port)
    distance = {}
    previous = {}
    #initialize distance and previous
    for dpid in switches:
        distance[dpid] = float('Inf')
        previous[dpid] = None
    distance[src] = 0
    Q = set(switches)
    print("Q=", Q)
    logger.debug("Q=", Q)
    while len(Q) > 0:
    	#find the node with minimum distance
        u = minimum_distance(distance, Q)
        Q.remove(u)
        # in a loop evaluate new distance for every node and set if its less than before
        for p in switches:
            if adjacency[u][p] is not None:
                w = 1
                if distance[u] + w < distance[p]:
                	# update distance in agreement with updated nodes
                    distance[p] = distance[u] + w
                    # update distance in agreement with updated nodes
                    previous[p] = u
    # in a recursive form generate vector which contains path (src to dest)
    r = []
    p = dst
    r.append(p)
    q = previous[p]
    # the path should be from src to dest so we reverse it
    while q is not None:
        if q == src:
            r.append(q)
            break
        p = q
        r.append(p)
        q = previous[p]
    r.reverse()
    if src == dst:
        path = [src]
    else:
        path = r
    # adding the ports
    r = []
    in_port = first_port
    # according to adjacent ports set in/out ports of switches
    for s1, s2 in zip(path[:-1], path[1:]):
        out_port = adjacency[s1][s2]
        r.append((s1, in_port, out_port))
        in_port = adjacency[s2][s1]
    # append the dest switch with its input and output port 
    r.append((dst, in_port, final_port))
    return r


class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = []

	# ls function for listing all attributes the object passed to it
    def ls(self, obj):
        print("\n".join([x for x in dir(obj) if x[0] != "_"]))
        logger.debug("\n".join([x for x in dir(obj) if x[0] != "_"]))

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto
        #Features request message
        # The controller sends a feature request to the switch upon session establishment.
        # This message is handled by the Ryu framework, so the Ryu application do not need to process this typically.
        parser = datapath.ofproto_parser
        match = datapath.ofproto_parser.OFPMatch(in_port=in_port, eth_dst=dst)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        # changing Flow entry message
        # The controller aim's to change the flow table by sending this message.
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY, instructions=inst)
        datapath.send_msg(mod)

	# CALLED UPON PATH IS DETERMINED AND WE WANT IT TO BE INSTALLED IN SWITCHES' FLOW TABLES
    def install_path(self, p, ev, src_mac, dst_mac):
        print("install_path is called")
        logger.debug("install_path is called")
        print "p=", p, " src_mac=", src_mac, " dst_mac=", dst_mac
        logger.debug("p=", p, " src_mac=", src_mac, " dst_mac=", dst_mac)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        #Features request message
        # The controller sends a feature request to the switch upon session establishment.
        # This message is handled by the Ryu framework, so the Ryu application do not need to process this typically.
        parser = datapath.ofproto_parser
        # SWITCH IN_PORT OUT_PORT FROM DIJKSTRA
        for sw, in_port, out_port in p:
            print src_mac,"->", dst_mac, "via ", sw, " in_port=", in_port, " out_port=", out_port
            logger.debug(src_mac,"->", dst_mac, "via ", sw, " in_port=", in_port, " out_port=", out_port)
            # finding switch that is matched with applied setting for switch id and mad addr
            print src_mac,"->", dst_mac, "via ", sw, " in_port=", in_port, " out_port=", out_port
            logger.debug(src_mac,"->", dst_mac, "via ", sw, " in_port=", in_port, " out_port=", out_port)
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            # action for adding output port
            actions = [parser.OFPActionOutput(out_port)]
            # finding the in agreement switch 
            datapath = self.datapath_list[int(sw) - 1]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            # apply the action that is being generated
            mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=0, hard_timeout=0, priority=1, instructions=inst)
            #broadcast openflow item
            datapath.send_msg(mod)

    # gets called upon switch config in the network
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
	    print("switch_features_handler is called")
	    logger.debug("switch_features_handler is called")
	    datapath = ev.msg.datapath
	    ofproto = datapath.ofproto
		# Upon session establishment, a feature request gets sent to switch by the controller. 
			# No need to process this message, it's handled by ryu framework
	    parser = datapath.ofproto_parser

	    match = parser.OFPMatch()
	    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
	    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		# Modify flow-entry message
	        # OFPFlowMod is for flow-mod message.
	    mod = datapath.ofproto_parser.OFPFlowMod(
	        datapath=datapath, match=match, cookie=0,
	        command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
	        priority=0, instructions=inst)
		# The controller sends this message in order to modify the flow table.
	    datapath.send_msg(mod)


	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		# GETS MSG LOADED WITH OPENFLOW EVENT MESSAGE 
	    msg = ev.msg
	    # GETS DATAPATH LOADED WITH MESSAGE.DATAPATH,
	    	# MESSAGE.DATAPATH IS INDEED AN INSTANCE OF RYU.CONTROLLER.DATAPATH WHICH HOLDS SPECS OF THE OPENFLOW SWITCH WE'VE RECIEVED THE MESSAGE FROM
	    datapath = msg.datapath
	    # ofproto module exports OpenFlow definitions, which mainly consist of constants appeared in sepcification for the negotiated OpenFlow version.
	    ofproto = datapath.ofproto
	    # ofproto_parser module exports OpenFlow wire message encoder and decoder for the negotiated OpenFlow version. 
			# Upon session establishment, a feature request gets sent to switch by the controller. 
			# No need to process this message, it's handled by ryu framework
	    parser = datapath.ofproto_parser
	    # gets in_port loaded with the port form which the packet came from
	    in_port = msg.match['in_port']
	    # capsulate msg.data as Packet type for further accesses to its fields
	    pkt = packet.Packet(msg.data)
	    # gets eth loaded with packet ehternet
	    eth = pkt.get_protocol(ethernet.ethernet)
	    print "eth.ethertype=", eth.ethertype
	    logger.debug("eth.ethertype=", eth.ethertype)
	    # avoid broadcast from Link Layer Discovery Protocol(LLDP)
	    if eth.ethertype == 35020:
	        return
        # packet ethernet source and destination
	    dst = eth.dst
	    src = eth.src
	    # gets dpid loaded with switch id in datapath 
	    dpid = datapath.id
	    self.mac_to_port.setdefault(dpid, {})

	    if src not in mymac.keys():
    	    # in case source is not known,
		    	# gets mymac loaded with each port of switches, which could be either hosts or communation of switches
	        mymac[src] = (dpid, in_port)
	        print "mymac=", mymac
	        logger.debug("mymac=", mymac)
	    if dst in mymac.keys():
	    	# in case switch and port of destination is known, 
	        p = get_path(mymac[src][0], mymac[dst][0], mymac[src][1], mymac[dst][1])
	        print(p)
	        logger.debug(p)
	        self.install_path(p, ev, src, dst)
	        out_port = p[0][2]
	    else:
	    	# if the destionation location is not known, 
	    		# flood
	        out_port = ofproto.OFPP_FLOOD
		# parser.OFPxxxx(datapath, ...) is a callable to prepare an OpenFlow message for the given switch. Can later be sent using datapath.send_msg.
			# xxxx represents the name of the message
			# arguments depend on the message
	    actions = [parser.OFPActionOutput(out_port)]
	    # install a flow to avoid packet_in next time
	    if out_port != ofproto.OFPP_FLOOD:
	        match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
	    data = None
	    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
	        data = msg.data
		# parser.OFPxxxx(datapath, ...) is a callable to prepare an OpenFlow message for the given switch. Can later be sent using datapath.send_msg.
		# xxxx represents the name of the message
		# arguments depend on the message
	    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
		# queue an OpenFlow message to send to the corresponding switch.
			# if msg.xid is None, set_xid() automatically gets called to resolve xid.
	    datapath.send_msg(out)


	@set_ev_cls(event.EventSwitchEnter)
	def get_topology_data(self, ev):
	    global switches
	    # get_switch() gets self.switch_list loaded with switches ids
	    switch_list = get_switch(self.topology_api_app, None)
	    switches = [switch.dp.id for switch in switch_list]
	    self.datapath_list = [switch.dp for switch in switch_list]
	    self.datapath_list.sort(key=lambda dp: dp.id, reverse= False)
	    print "self.datapath_list=", self.datapath_list
	    logger.debug("self.datapath_list=", self.datapath_list)
	    print("switches=", switches)
	    logger.debug("switches=", switches)
	    links_list = get_link(self.topology_api_app, None)
	    mylinks = [(link.src.dpid, link.dst.dpid, link.src.port_no, link.dst.port_no) for link in links_list]
		# adjacency map [sw1][sw2]->port from sw1 to sw2,
			# in which port1 and port2 represent output ports of each link
	    for s1, s2, port1, port2 in mylinks:
	        adjacency[s1][s2] = port1
	        adjacency[s2][s1] = port2
	        print s1,s2,port1,port2
	        logger.debug(s1,s2,port1,port2)


#Main
logger = logging.getLogger('myapp')
hdlr = logging.FileHandler('myapp.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(logging.DEBUG)