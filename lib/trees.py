"""
Attack tree generation utilities for diagnosability evaluation.

This module provides functions to generate random attack trees and
construct specific use-case scenarios like e-commerce platform security.
"""

import networkx as nx
import random
from typing import Dict, List, Tuple, Any


def generate_random_tree(num_nodes: int, seed: int = 42) -> Tuple[nx.DiGraph, Dict[str, Any]]:
    """
    Generate a random attack tree with time constraints.
    
    Args:
        num_nodes: Total number of nodes in the tree (10-25)
        seed: Random seed for reproducibility
    
    Returns:
        Tuple of (tree, node_attributes)
        tree: NetworkX DiGraph representing the attack tree
        node_attributes: Dict mapping node IDs to their properties
    """
    random.seed(seed + num_nodes)  # Ensure different trees for different sizes
    
    # Create directed graph
    tree = nx.DiGraph()
    node_attrs = {}
    
    # Generate nodes with IDs
    node_ids = [f"node_{i:02d}" for i in range(num_nodes)]
    
    # Add all nodes to graph
    for node_id in node_ids:
        tree.add_node(node_id)
    
    # Create tree structure (ensure it's a proper tree)
    # Start with root node
    root_id = node_ids[0]
    remaining_nodes = node_ids[1:]
    
    # Build tree by randomly attaching nodes
    for node_id in remaining_nodes:
        # Choose a random parent from existing nodes
        potential_parents = [n for n in tree.nodes() if n != node_id]
        parent_id = random.choice(potential_parents)
        tree.add_edge(parent_id, node_id)
    
    # Identify leaf nodes (nodes with no children)
    leaf_nodes = [n for n in tree.nodes() if tree.out_degree(n) == 0]
    
    # Assign attributes to each node
    for node_id in node_ids:
        is_leaf = node_id in leaf_nodes
        
        if is_leaf:
            # Leaf nodes: basic attack actions
            time_start = random.randint(0, 5)
            time_end = time_start + random.randint(2, 10)
            duration = random.randint(1, 4)
            cost = random.randint(1, 15)
            gate_type = None
        else:
            # Non-leaf nodes: intermediate goals with gates
            time_start = random.randint(0, 8)
            time_end = time_start + random.randint(3, 12)
            duration = random.randint(1, 3)
            cost = random.randint(0, 8)
            gate_type = random.choice(['AND', 'OR'])
            
            # SAND gates are less common
            if random.random() < 0.1:  # 10% chance
                gate_type = 'SAND'
        
        node_attrs[node_id] = {
            'time_interval': [time_start, time_end],
            'duration': duration,
            'cost': cost,
            'gate_type': gate_type,
            'is_leaf': is_leaf
        }
    
    # Ensure tree is connected and has reasonable structure
    if not nx.is_weakly_connected(tree):
        # Fix connectivity issues
        components = list(nx.weakly_connected_components(tree))
        for i in range(1, len(components)):
            # Connect each component to the main component
            main_node = list(components[0])[0]
            comp_node = list(components[i])[0]
            tree.add_edge(main_node, comp_node)
    
    return tree, node_attrs


def ecommerce_tree() -> Tuple[nx.DiGraph, Dict[str, Any]]:
    """
    Construct a realistic e-commerce platform attack tree for insider threat scenario.
    
    Models an insider threat attempting to exfiltrate credit card database
    from a cloud-hosted e-commerce platform.
    
    Returns:
        Tuple of (tree, node_attributes)
    """
    tree = nx.DiGraph()
    node_attrs = {}
    
    # Define the attack tree structure
    # Root goal: Credit card DB exfiltrated
    root = "cc_db_exfiltrated"
    
    # Intermediate nodes
    internal_access = "internal_access"
    db_access = "database_access"
    data_extraction = "data_extraction"
    
    # Leaf nodes (atomic attacks)
    spear_phish = "spear_phish_dev"
    auth_exploit = "auth_service_exploit"
    privilege_esc = "privilege_escalation"
    network_lateral = "network_lateral_movement"
    db_creds = "steal_db_credentials"
    exfil_channel = "establish_exfil_channel"
    
    # Build tree structure
    nodes = [
        root, internal_access, db_access, data_extraction,
        spear_phish, auth_exploit, privilege_esc, network_lateral,
        db_creds, exfil_channel
    ]
    
    for node in nodes:
        tree.add_node(node)
    
    # Define edges (parent -> child relationships)
    edges = [
        # Root requires both database access and data extraction capability
        (root, db_access),
        (root, data_extraction),
        
        # Database access requires internal access and credential theft
        (db_access, internal_access),
        (db_access, db_creds),
        
        # Internal access can be achieved through multiple paths
        (internal_access, spear_phish),
        (internal_access, auth_exploit),
        
        # Data extraction requires privilege escalation and exfiltration channel
        (data_extraction, privilege_esc),
        (data_extraction, exfil_channel),
        
        # Network lateral movement helps with privilege escalation
        (privilege_esc, network_lateral),
    ]
    
    for parent, child in edges:
        tree.add_edge(parent, child)
    
    # Define realistic MITRE ATT&CK-style time windows and costs
    node_attrs = {
        # Root goal - requires coordination of all sub-attacks
        root: {
            'time_interval': [0, 72],  # 0-72 hours (3 days max operation)
            'duration': 2,  # 2 hours to complete final exfiltration
            'cost': 5,
            'gate_type': 'AND',  # Requires both access and extraction
            'is_leaf': False
        },
        
        # Internal access - multiple possible paths
        internal_access: {
            'time_interval': [0, 48],  # 0-48 hours to gain internal access
            'duration': 1,
            'cost': 2,
            'gate_type': 'OR',  # Can use either spear phishing or auth exploit
            'is_leaf': False
        },
        
        # Database access - requires both internal access and credentials
        db_access: {
            'time_interval': [6, 60],  # 6-60 hours (after initial access)
            'duration': 2,
            'cost': 3,
            'gate_type': 'AND',  # Needs both internal access and credentials
            'is_leaf': False
        },
        
        # Data extraction capability
        data_extraction: {
            'time_interval': [12, 72],  # 12-72 hours (late in attack)
            'duration': 4,  # 4 hours to set up extraction
            'cost': 4,
            'gate_type': 'AND',  # Needs both privilege escalation and exfil channel
            'is_leaf': False
        },
        
        # Privilege escalation
        privilege_esc: {
            'time_interval': [8, 48],  # 8-48 hours
            'duration': 3,
            'cost': 6,
            'gate_type': 'OR',  # Can be achieved through lateral movement or other means
            'is_leaf': False
        },
        
        # Leaf nodes (atomic attacks)
        spear_phish: {
            'time_interval': [0, 24],  # 0-24 hours (early attack phase)
            'duration': 4,  # 4 hours to craft and execute spear phishing
            'cost': 8,  # Moderate cost for social engineering
            'gate_type': None,
            'is_leaf': True
        },
        
        auth_exploit: {
            'time_interval': [0, 12],  # 0-12 hours (quick exploitation)
            'duration': 2,  # 2 hours to exploit vulnerability
            'cost': 12,  # High cost due to exploit development/purchase
            'gate_type': None,
            'is_leaf': True
        },
        
        network_lateral: {
            'time_interval': [6, 36],  # 6-36 hours (after initial access)
            'duration': 6,  # 6 hours for lateral movement
            'cost': 10,  # High cost due to stealth requirements
            'gate_type': None,
            'is_leaf': True
        },
        
        db_creds: {
            'time_interval': [8, 48],  # 8-48 hours
            'duration': 3,  # 3 hours to locate and steal credentials
            'cost': 7,  # Moderate-high cost
            'gate_type': None,
            'is_leaf': True
        },
        
        exfil_channel: {
            'time_interval': [12, 60],  # 12-60 hours (late in attack)
            'duration': 5,  # 5 hours to establish secure exfiltration
            'cost': 9,  # High cost for covert channel
            'gate_type': None,
            'is_leaf': True
        }
    }
    
    return tree, node_attrs


def get_tree_statistics(tree: nx.DiGraph, node_attrs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate statistics for an attack tree.
    
    Args:
        tree: NetworkX DiGraph representing the attack tree
        node_attrs: Dictionary of node attributes
    
    Returns:
        Dictionary of tree statistics
    """
    leaf_nodes = [n for n in tree.nodes() if tree.out_degree(n) == 0]
    
    # Count gate types
    gate_counts = {'AND': 0, 'OR': 0, 'SAND': 0, 'None': 0}
    total_cost = 0
    time_spans = []
    
    for node_id, attrs in node_attrs.items():
        gate_type = attrs.get('gate_type', 'None')
        if gate_type in gate_counts:
            gate_counts[gate_type] += 1
        else:
            gate_counts['None'] += 1
        
        total_cost += attrs.get('cost', 0)
        
        time_interval = attrs.get('time_interval', [0, 1])
        time_spans.append(time_interval[1] - time_interval[0])
    
    return {
        'total_nodes': len(tree.nodes()),
        'leaf_nodes': len(leaf_nodes),
        'internal_nodes': len(tree.nodes()) - len(leaf_nodes),
        'total_edges': len(tree.edges()),
        'max_depth': nx.dag_longest_path_length(tree) if nx.is_dag(tree) else 0,
        'gate_counts': gate_counts,
        'total_cost': total_cost,
        'avg_time_span': sum(time_spans) / len(time_spans) if time_spans else 0,
        'max_time_span': max(time_spans) if time_spans else 0
    }


def validate_tree_structure(tree: nx.DiGraph, node_attrs: Dict[str, Any]) -> List[str]:
    """
    Validate attack tree structure and return list of issues found.
    
    Args:
        tree: NetworkX DiGraph representing the attack tree
        node_attrs: Dictionary of node attributes
    
    Returns:
        List of validation error messages (empty if valid)
    """
    issues = []
    
    # Check if tree is connected
    if not nx.is_weakly_connected(tree):
        issues.append("Tree is not connected")
    
    # Check if tree is acyclic
    if not nx.is_dag(tree):
        issues.append("Tree contains cycles")
    
    # Check for nodes without attributes
    for node_id in tree.nodes():
        if node_id not in node_attrs:
            issues.append(f"Node {node_id} missing attributes")
            continue
        
        attrs = node_attrs[node_id]
        
        # Check required attributes
        required_attrs = ['time_interval', 'duration', 'cost']
        for attr in required_attrs:
            if attr not in attrs:
                issues.append(f"Node {node_id} missing {attr}")
        
        # Validate time constraints
        if 'time_interval' in attrs:
            time_interval = attrs['time_interval']
            if len(time_interval) != 2 or time_interval[0] > time_interval[1]:
                issues.append(f"Node {node_id} has invalid time interval")
        
        # Validate gate types for non-leaf nodes
        if tree.out_degree(node_id) > 0:  # Non-leaf node
            if attrs.get('gate_type') not in ['AND', 'OR', 'SAND']:
                issues.append(f"Non-leaf node {node_id} has invalid gate type")
        else:  # Leaf node
            if attrs.get('gate_type') is not None:
                issues.append(f"Leaf node {node_id} should not have gate type")
    
    return issues
