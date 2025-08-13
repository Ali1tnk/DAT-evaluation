#!/usr/bin/env python3
"""
Generate 100 random timed attack trees for TAPAAL diagnosability evaluation.

This script creates random attack trees with 10-25 nodes each, converts them
to TAPAAL Timed-Arc Petri Net XML format, and generates corresponding CTL
diagnosability queries.

Output:
- models/tree_###.xml: TAPAAL XML files for each tree
- queries/tree_###.q: CTL query files for diagnosability checking

All random generation uses seed 42 for reproducibility.
"""

import os
import sys
from typing import List, Set
from tqdm import tqdm

# Add lib to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'lib'))

from lib.trees import generate_random_tree, validate_tree_structure, get_tree_statistics
from lib.tapaal import enhanced_tapaal_xml, diagnosability_query


def create_directories():
    """Create necessary output directories."""
    os.makedirs('models', exist_ok=True)
    os.makedirs('queries', exist_ok=True)


def select_observable_nodes(tree, node_attrs) -> Set[str]:
    """
    Select observable nodes for diagnosability testing.
    Strategy: All non-leaf nodes are observable (representing internal sensors/monitors).
    
    Args:
        tree: NetworkX DiGraph representing the attack tree
        node_attrs: Dictionary of node attributes
    
    Returns:
        Set of observable node IDs
    """
    observable = set()
    
    for node_id in tree.nodes():
        attrs = node_attrs.get(node_id, {})
        is_leaf = attrs.get('is_leaf', tree.out_degree(node_id) == 0)
        
        # Non-leaf nodes are observable (internal system states)
        if not is_leaf:
            observable.add(node_id)
    
    return observable


def generate_tree_batch(start_id: int, count: int, min_nodes: int = 10, max_nodes: int = 25) -> List[dict]:
    """
    Generate a batch of random attack trees.
    
    Args:
        start_id: Starting tree ID number
        count: Number of trees to generate
        min_nodes: Minimum number of nodes per tree
        max_nodes: Maximum number of nodes per tree
    
    Returns:
        List of dictionaries containing tree metadata
    """
    import random
    random.seed(42)  # Fixed seed for reproducibility
    
    trees_info = []
    
    for i in range(count):
        tree_id = start_id + i
        
        # Randomly select tree size
        num_nodes = random.randint(min_nodes, max_nodes)
        
        # Generate tree with unique seed for each tree
        tree, node_attrs = generate_random_tree(num_nodes, seed=42 + tree_id)
        
        # Validate tree structure
        issues = validate_tree_structure(tree, node_attrs)
        if issues:
            print(f"Warning: Tree {tree_id:03d} has issues: {issues}")
            # Continue anyway for evaluation purposes
        
        # Get tree statistics
        stats = get_tree_statistics(tree, node_attrs)
        
        # Select observable nodes (all non-leaf nodes)
        observable_nodes = select_observable_nodes(tree, node_attrs)
        
        # Generate TAPAAL XML
        xml_content = enhanced_tapaal_xml(tree, node_attrs, str(tree_id))
        
        # Generate CTL query for diagnosability
        query_content = diagnosability_query(tree, observable_nodes, str(tree_id))
        
        # Save XML file
        xml_filename = f"models/tree_{tree_id:03d}.xml"
        with open(xml_filename, 'w', encoding='utf-8') as f:
            f.write(xml_content)
        
        # Save query file
        query_filename = f"queries/tree_{tree_id:03d}.q"
        with open(query_filename, 'w', encoding='utf-8') as f:
            f.write(query_content)
        
        # Store tree information
        tree_info = {
            'tree_id': tree_id,
            'num_nodes': num_nodes,
            'observable_nodes': len(observable_nodes),
            'observable_coverage': len(observable_nodes) / num_nodes,
            'xml_file': xml_filename,
            'query_file': query_filename,
            'stats': stats
        }
        
        trees_info.append(tree_info)
    
    return trees_info


def save_tree_metadata(trees_info: List[dict]):
    """
    Save metadata about generated trees to a summary file.
    
    Args:
        trees_info: List of tree information dictionaries
    """
    import json
    
    # Create summary statistics
    summary = {
        'total_trees': len(trees_info),
        'node_count_range': {
            'min': min(t['num_nodes'] for t in trees_info),
            'max': max(t['num_nodes'] for t in trees_info),
            'avg': sum(t['num_nodes'] for t in trees_info) / len(trees_info)
        },
        'observable_coverage': {
            'min': min(t['observable_coverage'] for t in trees_info),
            'max': max(t['observable_coverage'] for t in trees_info),
            'avg': sum(t['observable_coverage'] for t in trees_info) / len(trees_info)
        },
        'trees': trees_info
    }
    
    # Save to JSON file
    with open('tree_metadata.json', 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    
    print(f"Tree metadata saved to tree_metadata.json")
    print(f"Generated {len(trees_info)} trees with {summary['node_count_range']['min']}-{summary['node_count_range']['max']} nodes each")
    print(f"Average observable coverage: {summary['observable_coverage']['avg']:.2%}")


def main():
    """Main function to generate all attack trees."""
    print("Generating 100 random timed attack trees for diagnosability evaluation...")
    print("Using fixed seed 42 for reproducibility")
    
    # Create output directories
    create_directories()
    
    # Generate 100 trees with IDs 001-100
    trees_info = []
    
    # Generate trees in batches with progress bar
    batch_size = 10
    num_batches = 100 // batch_size
    
    with tqdm(total=100, desc="Generating trees") as pbar:
        for batch_idx in range(num_batches):
            start_id = batch_idx * batch_size + 1
            batch_info = generate_tree_batch(start_id, batch_size)
            trees_info.extend(batch_info)
            pbar.update(batch_size)
    
    # Save metadata about all generated trees
    save_tree_metadata(trees_info)
    
    print(f"\nSuccessfully generated:")
    print(f"- 100 TAPAAL XML files in models/ directory")
    print(f"- 100 CTL query files in queries/ directory")
    print(f"- Tree metadata in tree_metadata.json")
    print(f"\nNext step: Run './run_tapaal.sh' to execute TAPAAL verification")


if __name__ == "__main__":
    main()
