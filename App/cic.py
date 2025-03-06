import time
import statistics
from collections import defaultdict
import ipaddress
from scapy.all import IP, TCP, UDP


class FlowRecord:
    """Class to store and analyze network flow information"""

    def __init__(self, src_ip, dst_ip, src_port=None, dst_port=None, protocol=None):
        # Flow identification
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        # Flow timestamps
        self.start_time = time.time()
        self.last_time = self.start_time
        self.flow_duration = 0

        # Packet counters
        self.fwd_packets = 0  # Source to destination
        self.bwd_packets = 0  # Destination to source
        self.total_packets = 0

        # Byte counters
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.total_bytes = 0

        # Packet length statistics
        self.packet_lengths = []
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []

        # Inter-arrival time statistics
        self.flow_iat = []  # Inter-arrival times
        self.fwd_iat = []  # Forward inter-arrival times
        self.bwd_iat = []  # Backward inter-arrival times

        # TCP flags (for TCP flows)
        self.fwd_syn_flags = 0
        self.bwd_syn_flags = 0
        self.fwd_fin_flags = 0
        self.bwd_fin_flags = 0
        self.fwd_rst_flags = 0
        self.bwd_rst_flags = 0
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_ack_flags = 0
        self.bwd_ack_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0

        # Active/Inactive times
        self.last_active_time = self.start_time
        self.active_times = []
        self.inactive_times = []
        self.active_threshold = 5.0  # 5 seconds of inactivity defines a new burst

        # Flow state
        self.is_active = True

    def update_with_packet(self, packet, direction="forward"):
        """Update flow statistics with a new packet"""
        current_time = float(packet.sniff_time.timestamp())
        packet_length = int(packet.length)
        is_forward = (direction == "forward")

        # Update timestamp information
        if self.total_packets > 0:
            iat = current_time - self.last_time
            self.flow_iat.append(iat)

            if is_forward:
                self.fwd_iat.append(iat)
            else:
                self.bwd_iat.append(iat)

            # Check if we need to update active/inactive times
            if iat > self.active_threshold:
                self.inactive_times.append(iat)
                self.active_times.append(current_time - self.last_active_time)
                self.last_active_time = current_time

        self.last_time = current_time
        self.flow_duration = self.last_time - self.start_time

        # Update packet and byte counters
        self.total_packets += 1
        self.total_bytes += packet_length
        self.packet_lengths.append(packet_length)

        if is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += packet_length
            self.fwd_packet_lengths.append(packet_length)
        else:
            self.bwd_packets += 1
            self.bwd_bytes += packet_length
            self.bwd_packet_lengths.append(packet_length)

        # Update TCP flags if applicable
        if hasattr(packet, 'tcp'):
            flags = int(packet.tcp.flags, 16)

            if is_forward:
                if flags & 0x02:  # SYN flag
                    self.fwd_syn_flags += 1
                if flags & 0x01:  # FIN flag
                    self.fwd_fin_flags += 1
                if flags & 0x04:  # RST flag
                    self.fwd_rst_flags += 1
                if flags & 0x08:  # PSH flag
                    self.fwd_psh_flags += 1
                if flags & 0x10:  # ACK flag
                    self.fwd_ack_flags += 1
                if flags & 0x20:  # URG flag
                    self.fwd_urg_flags += 1
            else:
                if flags & 0x02:  # SYN flag
                    self.bwd_syn_flags += 1
                if flags & 0x01:  # FIN flag
                    self.bwd_fin_flags += 1
                if flags & 0x04:  # RST flag
                    self.bwd_rst_flags += 1
                if flags & 0x08:  # PSH flag
                    self.bwd_psh_flags += 1
                if flags & 0x10:  # ACK flag
                    self.bwd_ack_flags += 1
                if flags & 0x20:  # URG flag
                    self.bwd_urg_flags += 1

    def get_stats(self):
        """Return statistical information about the flow"""
        stats = {
            # Flow identification
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,

            # Basic flow metrics
            'flow_duration': self.flow_duration,
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'fwd_packets': self.fwd_packets,
            'bwd_packets': self.bwd_packets,
            'fwd_bytes': self.fwd_bytes,
            'bwd_bytes': self.bwd_bytes,

            # Derived metrics
            'flow_bytes_per_sec': self.total_bytes / max(self.flow_duration, 0.001),
            'flow_packets_per_sec': self.total_packets / max(self.flow_duration, 0.001),
        }

        # Add packet length statistics if available
        if self.packet_lengths:
            stats.update({
                'packet_length_min': min(self.packet_lengths),
                'packet_length_max': max(self.packet_lengths),
                'packet_length_mean': statistics.mean(self.packet_lengths),
                'packet_length_std': statistics.stdev(self.packet_lengths) if len(self.packet_lengths) > 1 else 0,
            })

        # Add forward packet length statistics if available
        if self.fwd_packet_lengths:
            stats.update({
                'fwd_packet_length_min': min(self.fwd_packet_lengths),
                'fwd_packet_length_max': max(self.fwd_packet_lengths),
                'fwd_packet_length_mean': statistics.mean(self.fwd_packet_lengths),
                'fwd_packet_length_std': statistics.stdev(self.fwd_packet_lengths) if len(
                    self.fwd_packet_lengths) > 1 else 0,
            })

        # Add backward packet length statistics if available
        if self.bwd_packet_lengths:
            stats.update({
                'bwd_packet_length_min': min(self.bwd_packet_lengths),
                'bwd_packet_length_max': max(self.bwd_packet_lengths),
                'bwd_packet_length_mean': statistics.mean(self.bwd_packet_lengths),
                'bwd_packet_length_std': statistics.stdev(self.bwd_packet_lengths) if len(
                    self.bwd_packet_lengths) > 1 else 0,
            })

        # Add flow IAT statistics if available
        if self.flow_iat:
            stats.update({
                'flow_iat_min': min(self.flow_iat),
                'flow_iat_max': max(self.flow_iat),
                'flow_iat_mean': statistics.mean(self.flow_iat),
                'flow_iat_std': statistics.stdev(self.flow_iat) if len(self.flow_iat) > 1 else 0,
            })

        # Add forward IAT statistics if available
        if self.fwd_iat:
            stats.update({
                'fwd_iat_min': min(self.fwd_iat),
                'fwd_iat_max': max(self.fwd_iat),
                'fwd_iat_mean': statistics.mean(self.fwd_iat),
                'fwd_iat_std': statistics.stdev(self.fwd_iat) if len(self.fwd_iat) > 1 else 0,
                'fwd_iat_total': sum(self.fwd_iat),
            })

        # Add backward IAT statistics if available
        if self.bwd_iat:
            stats.update({
                'bwd_iat_min': min(self.bwd_iat),
                'bwd_iat_max': max(self.bwd_iat),
                'bwd_iat_mean': statistics.mean(self.bwd_iat),
                'bwd_iat_std': statistics.stdev(self.bwd_iat) if len(self.bwd_iat) > 1 else 0,
                'bwd_iat_total': sum(self.bwd_iat),
            })

        # Add TCP flags information
        if self.protocol == 'TCP':
            stats.update({
                'fwd_syn_flags': self.fwd_syn_flags,
                'bwd_syn_flags': self.bwd_syn_flags,
                'fwd_fin_flags': self.fwd_fin_flags,
                'bwd_fin_flags': self.bwd_fin_flags,
                'fwd_rst_flags': self.fwd_rst_flags,
                'bwd_rst_flags': self.bwd_rst_flags,
                'fwd_psh_flags': self.fwd_psh_flags,
                'bwd_psh_flags': self.bwd_psh_flags,
                'fwd_ack_flags': self.fwd_ack_flags,
                'bwd_ack_flags': self.bwd_ack_flags,
                'fwd_urg_flags': self.fwd_urg_flags,
                'bwd_urg_flags': self.bwd_urg_flags,
            })

        # Add active/inactive time statistics if available
        if self.active_times:
            stats.update({
                'active_min': min(self.active_times),
                'active_max': max(self.active_times),
                'active_mean': statistics.mean(self.active_times),
                'active_std': statistics.stdev(self.active_times) if len(self.active_times) > 1 else 0,
            })

        if self.inactive_times:
            stats.update({
                'inactive_min': min(self.inactive_times),
                'inactive_max': max(self.inactive_times),
                'inactive_mean': statistics.mean(self.inactive_times),
                'inactive_std': statistics.stdev(self.inactive_times) if len(self.inactive_times) > 1 else 0,
            })

        return stats


class FlowManager:
    """Manages multiple network flows and their lifecycle"""

    def __init__(self, flow_timeout=120, activity_timeout=5):
        self.flows = {}  # Dictionary to store active flows
        self.completed_flows = []  # List to store completed flows
        self.flow_timeout = flow_timeout  # Time to keep inactive flows (seconds)
        self.activity_timeout = activity_timeout  # Time to consider a flow inactive

    def get_flow_key(self, packet):
        """Generate a unique key for a flow based on packet information"""
        if 'ip' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            # Determine protocol and ports
            if hasattr(packet, 'tcp'):
                protocol = 'TCP'
                src_port = int(packet.tcp.srcport)
                dst_port = int(packet.tcp.dstport)
            elif hasattr(packet, 'udp'):
                protocol = 'UDP'
                src_port = int(packet.udp.srcport)
                dst_port = int(packet.udp.dstport)
            else:
                protocol = 'OTHER'
                src_port = 0
                dst_port = 0

            # Create a bi-directional flow key (smaller IP address first)
            if ipaddress.ip_address(src_ip) < ipaddress.ip_address(dst_ip):
                flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
                direction = "forward"
            else:
                flow_key = (dst_ip, src_ip, dst_port, src_port, protocol)
                direction = "backward"

            return flow_key, direction

        return None, None

    def process_packet(self, packet):
        """Process a packet and update the corresponding flow"""
        flow_key, direction = self.get_flow_key(packet)

        if flow_key is None:
            return None

        if flow_key not in self.flows:
            # Create a new flow record
            src_ip, dst_ip, src_port, dst_port, protocol = flow_key
            flow = FlowRecord(src_ip, dst_ip, src_port, dst_port, protocol)
            self.flows[flow_key] = flow
        else:
            flow = self.flows[flow_key]

        # Update flow with the new packet
        flow.update_with_packet(packet, direction)

        return flow

    def check_timeouts(self, current_time=None):
        """Check for timed-out flows and move them to completed flows"""
        if current_time is None:
            current_time = time.time()

        timed_out_keys = []
        for key, flow in self.flows.items():
            # Check if flow has timed out
            if current_time - flow.last_time > self.flow_timeout:
                timed_out_keys.append(key)

        # Move timed-out flows to completed flows
        for key in timed_out_keys:
            self.completed_flows.append(self.flows[key])
            del self.flows[key]

    def get_all_flows(self):
        """Return all active and completed flows"""
        all_flows = self.completed_flows.copy()
        all_flows.extend(list(self.flows.values()))
        return all_flows

    def get_flow_stats(self):
        """Return statistics for all flows"""
        return [flow.get_stats() for flow in self.get_all_flows()]