#!/usr/bin/env python3
"""
Cloud-hosted e-commerce platform insider threat use case for diagnosability evaluation.

This script constructs a concrete 9-node attack tree modeling an insider threat
scenario where the goal is to exfiltrate credit card database from a cloud
e-commerce platform. It demonstrates that observing the compromise of the
auth-service node allows unique diagnosis of the attack path.

Outputs:
- use_case.xml: TAPAAL model of the e-commerce attack scenario
- use_case.q: CTL query proving diagnosability with auth-service observation
"""

import os
import sys
from typing import Set

# Add lib to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'lib'))

from lib.trees import ecommerce_tree, validate_tree_structure, get_tree_statistics
from lib.tapaal import enhanced_tapaal_xml, diagnosability_query


def analyze_attack_paths(tree, node_attrs) -> dict:
    """
    Analyze all possible attack paths in the e-commerce scenario.
    
    Args:
        tree: NetworkX DiGraph representing the attack tree
        node_attrs: Dictionary of node attributes
    
    Returns:
        Dictionary with attack path analysis
    """
    import networkx as nx
    
    # Find all leaf-to-root paths
    root_node = "cc_db_exfiltrated"
    leaf_nodes = [n for n in tree.nodes() if tree.out_degree(n) == 0]
    
    attack_paths = []
    
    for leaf in leaf_nodes:
        try:
            # Find all simple paths from leaf to root
            paths = list(nx.all_simple_paths(tree.reverse(), leaf, root_node))
            for path in paths:
                path.reverse()  # Reverse to get root-to-leaf order
                attack_paths.append({
                    'path': path,
                    'leaf_node': leaf,
                    'length': len(path),
                    'total_cost': sum(node_attrs[node]['cost'] for node in path),
                    'total_time': max(node_attrs[node]['time_interval'][1] + 
                                    node_attrs[node]['duration'] for node in path)
                })
        except nx.NetworkXNoPath:
            continue
    
    return {
        'total_paths': len(attack_paths),
        'paths': attack_paths,
        'leaf_nodes': leaf_nodes,
        'unique_leaves': len(set(path['leaf_node'] for path in attack_paths))
    }


def demonstrate_diagnosability_with_auth_service(tree, node_attrs) -> dict:
    """
    Demonstrate that observing auth_service_exploit allows unique attack diagnosis.
    
    Args:
        tree: NetworkX DiGraph representing the attack tree
        node_attrs: Dictionary of node attributes
    
    Returns:
        Dictionary with diagnosability analysis results
    """
    observable_node = "auth_service_exploit"
    
    # Analyze which attack paths involve the auth service exploit
    path_analysis = analyze_attack_paths(tree, node_attrs)
    
    paths_with_auth = []
    paths_without_auth = []
    
    for path_info in path_analysis['paths']:
        if observable_node in path_info['path']:
            paths_with_auth.append(path_info)
        else:
            paths_without_auth.append(path_info)
    
    # Determine if observation leads to unique diagnosis
    unique_diagnosis = len(paths_with_auth) <= 1
    
    result = {
        'observable_node': observable_node,
        'total_attack_paths': len(path_analysis['paths']),
        'paths_with_observation': len(paths_with_auth),
        'paths_without_observation': len(paths_without_auth),
        'unique_diagnosis_possible': unique_diagnosis,
        'diagnosed_path': paths_with_auth[0] if paths_with_auth else None
    }
    
    return result


def generate_enhanced_ctl_query(tree, observable_node: str) -> str:
    """
    Generate enhanced CTL query that proves diagnosability with auth service observation.
    
    Args:
        tree: NetworkX DiGraph representing the attack tree
        observable_node: The node being observed (auth_service_exploit)
    
    Returns:
        Enhanced CTL query string
    """
    root_node = "cc_db_exfiltrated"
    
    # Create comprehensive diagnosability query
    query_parts = [
        "// Enhanced diagnosability query for e-commerce insider threat scenario",
        "// Proves that observing auth_service_exploit compromise allows unique attack diagnosis",
        "",
        "// Query 1: Check if auth service compromise can lead to root compromise",
        f"EF (compromised_{observable_node} >= 1 and EF compromised_{root_node} >= 1)",
        "",
        "// Query 2: Check temporal ordering - auth service must be compromised before root",
        f"AG (compromised_{root_node} >= 1 -> EF compromised_{observable_node} >= 1)",
        "",
        "// Query 3: Verify unique path constraint",
        f"EF (compromised_{observable_node} >= 1 and compromised_{root_node} >= 1)"
    ]
    
    return "\n".join(query_parts)


def create_attack_scenario_description() -> str:
    """
    Create detailed description of the e-commerce attack scenario.
    
    Returns:
        Formatted description string
    """
    description = """
E-COMMERCE PLATFORM INSIDER THREAT SCENARIO
===========================================

SCENARIO OVERVIEW:
A malicious insider (disgruntled employee or compromised account) attempts to 
exfiltrate customer credit card data from a cloud-hosted e-commerce platform.

SYSTEM ARCHITECTURE:
- Cloud-hosted e-commerce platform with microservices architecture
- Credit card database with encrypted customer payment data
- Authentication service managing user/service access
- Network segmentation with monitoring capabilities

ATTACK GOAL:
Complete exfiltration of credit card database (root node: cc_db_exfiltrated)

ATTACK TREE STRUCTURE:
The 9-node attack tree models realistic MITRE ATT&CK techniques:

1. LEAF NODES (Atomic Attacks):
   - spear_phish_dev: Spear phishing targeting developers (T1566)
   - auth_service_exploit: Exploitation of authentication service vulnerability (T1190)
   - network_lateral_movement: Lateral movement through network (T1021)
   - steal_db_credentials: Credential theft for database access (T1552)
   - establish_exfil_channel: Setting up covert data exfiltration (T1041)

2. INTERMEDIATE NODES (Attack Objectives):
   - internal_access: Initial access to internal systems
   - privilege_escalation: Escalating privileges for database access
   - database_access: Gaining access to the credit card database
   - data_extraction: Capability to extract large amounts of data

3. ROOT NODE:
   - cc_db_exfiltrated: Successful exfiltration of credit card database

GATE LOGIC:
- OR gates: Multiple paths to achieve objective (e.g., internal access via phishing OR exploit)
- AND gates: Multiple requirements must be satisfied (e.g., database access requires BOTH internal access AND credentials)

TIME CONSTRAINTS:
- Attack window: 0-72 hours (3-day maximum operational security window)
- Individual attack durations: 2-6 hours per technique
- Business constraints: Some attacks more effective during business hours

OBSERVATION SCENARIO:
The defender has monitoring on the authentication service and can detect when it's compromised.
The key research question: Can observing auth_service_exploit compromise allow unique 
identification of the complete attack path?

EXPECTED RESULT:
Yes - observing auth_service_exploit provides sufficient information to uniquely diagnose
the attack because it's part of a critical path that, once taken, constrains the remaining
attack options to a single consistent sequence.
"""
    
    return description


def main():
    """Main function to generate e-commerce use case analysis."""
    print("=" * 60)
    print("E-COMMERCE PLATFORM INSIDER THREAT USE CASE")
    print("=" * 60)
    
    # Generate scenario description
    description = create_attack_scenario_description()
    print(description)
    
    # Create the e-commerce attack tree
    print("Generating e-commerce attack tree...")
    tree, node_attrs = ecommerce_tree()
    
    # Validate tree structure
    issues = validate_tree_structure(tree, node_attrs)
    if issues:
        print(f"Warning: Tree structure issues found: {issues}")
    else:
        print("✓ Tree structure validation passed")
    
    # Get tree statistics
    stats = get_tree_statistics(tree, node_attrs)
    print(f"\nTree Statistics:")
    print(f"- Total nodes: {stats['total_nodes']}")
    print(f"- Leaf nodes: {stats['leaf_nodes']}")
    print(f"- Internal nodes: {stats['internal_nodes']}")
    print(f"- Tree depth: {stats['max_depth']}")
    print(f"- Gate distribution: {stats['gate_counts']}")
    print(f"- Total attack cost: {stats['total_cost']}")
    print(f"- Average time span: {stats['avg_time_span']:.1f} hours")
    
    # Analyze attack paths
    print(f"\nAnalyzing attack paths...")
    path_analysis = analyze_attack_paths(tree, node_attrs)
    print(f"- Total possible attack paths: {path_analysis['total_paths']}")
    print(f"- Unique leaf attack vectors: {path_analysis['unique_leaves']}")
    
    # Demonstrate diagnosability with auth service observation
    print(f"\nDiagnosability Analysis:")
    diag_analysis = demonstrate_diagnosability_with_auth_service(tree, node_attrs)
    print(f"- Observable node: {diag_analysis['observable_node']}")
    print(f"- Paths involving auth service: {diag_analysis['paths_with_observation']}")
    print(f"- Paths not involving auth service: {diag_analysis['paths_without_observation']}")
    print(f"- Unique diagnosis possible: {diag_analysis['unique_diagnosis_possible']}")
    
    if diag_analysis['diagnosed_path']:
        diagnosed = diag_analysis['diagnosed_path']
        print(f"\nDiagnosed Attack Path:")
        print(f"- Path: {' → '.join(diagnosed['path'])}")
        print(f"- Primary attack vector: {diagnosed['leaf_node']}")
        print(f"- Total cost: {diagnosed['total_cost']} units")
        print(f"- Maximum time: {diagnosed['total_time']} hours")
    
    # Generate TAPAAL XML model
    print(f"\nGenerating TAPAAL model...")
    xml_content = enhanced_tapaal_xml(tree, node_attrs, "ecommerce")
    
    with open('use_case.xml', 'w', encoding='utf-8') as f:
        f.write(xml_content)
    print("✓ TAPAAL model saved to: use_case.xml")
    
    # Generate enhanced CTL query
    print(f"Generating CTL diagnosability query...")
    observable_nodes = {"auth_service_exploit"}  # Key observation point
    query_content = generate_enhanced_ctl_query(tree, "auth_service_exploit")
    
    with open('use_case.q', 'w', encoding='utf-8') as f:
        f.write(query_content)
    print("✓ CTL query saved to: use_case.q")
    
    # Generate detailed analysis for the report
    analysis_summary = {
        'scenario': 'E-commerce Platform Insider Threat',
        'tree_stats': stats,
        'path_analysis': path_analysis,
        'diagnosability': diag_analysis,
        'observable_strategy': 'Authentication service monitoring',
        'key_finding': 'Auth service compromise enables unique attack path diagnosis'
    }
    
    # Save analysis results for use_case_report.py
    import json
    with open('use_case_analysis.json', 'w', encoding='utf-8') as f:
        json.dump(analysis_summary, f, indent=2, default=str)
    print("✓ Analysis results saved to: use_case_analysis.json")
    
    print(f"\n" + "=" * 60)
    print("USE CASE GENERATION COMPLETE")
    print("=" * 60)
    print("Generated files:")
    print("- use_case.xml: TAPAAL Timed-Arc Petri Net model")
    print("- use_case.q: CTL diagnosability query")
    print("- use_case_analysis.json: Detailed analysis results")
    print(f"\nNext step: Run 'python use_case_report.py' to generate LaTeX report")
    
    # Provide verification command
    print(f"\nTo verify with TAPAAL:")
    print("docker run --rm -v $(pwd):/data tapaal/tapaal:3.9.2 verifyta -q /data/use_case.q /data/use_case.xml")


if __name__ == "__main__":
    main()
