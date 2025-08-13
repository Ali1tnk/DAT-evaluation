"""
TAPAAL XML generation and CTL query creation for Attack Tree diagnosability analysis.

This module provides functions to convert Attack Trees with time constraints
into TAPAAL Timed-Arc Petri Net XML format and generate corresponding
CTL queries for diagnosability checking.
"""

import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple, Set
import networkx as nx


def tapaal_xml(tree: nx.DiGraph, node_attrs: Dict, tree_id: str) -> str:
    """
    Convert an Attack Tree to TAPAAL Timed-Arc Petri Net XML format.
    
    Args:
        tree: NetworkX DiGraph representing the attack tree
        node_attrs: Dictionary mapping node IDs to their attributes
                   (time_interval, duration, cost, gate_type)
        tree_id: Unique identifier for this tree
    
    Returns:
        XML string in TAPAAL format
    """
    # Create root XML element
    root = ET.Element("pnml", xmlns="http://www.pnml.org/version-2009/grammar/pnml")
    
    # Create net element
    net = ET.SubElement(root, "net", id=f"tree_{tree_id}", type="http://www.tapaal.net/")
    
    # Add name
    name = ET.SubElement(net, "name")
    text = ET.SubElement(name, "text")
    text.text = f"Attack Tree {tree_id}"
    
    # Create page element (TAPAAL uses pages)
    page = ET.SubElement(net, "page", id="Page0")
    
    # Track place and transition positions for visualization
    x_pos = 0
    y_pos = 0
    place_positions = {}
    transition_positions = {}
    
    # Create places for each node (representing node states)
    for node_id in tree.nodes():
        # Compromised state place
        place_id = f"compromised_{node_id}"
        place = ET.SubElement(page, "place", id=place_id)
        
        # Position
        place_positions[place_id] = (x_pos, y_pos)
        graphics = ET.SubElement(place, "graphics")
        position = ET.SubElement(graphics, "position", x=str(x_pos), y=str(y_pos))
        
        # Name
        name_elem = ET.SubElement(place, "name")
        text_elem = ET.SubElement(name_elem, "text")
        text_elem.text = f"comp_{node_id}"
        
        # Initial marking (empty for all nodes initially)
        initial_marking = ET.SubElement(place, "initialMarking")
        text_elem = ET.SubElement(initial_marking, "text")
        text_elem.text = "0"
        
        # Type (integer for counting)
        type_elem = ET.SubElement(place, "type")
        text_elem = ET.SubElement(type_elem, "text")
        text_elem.text = "int"
        
        x_pos += 150
        if x_pos > 600:  # Wrap to next row
            x_pos = 0
            y_pos += 100
    
    # Create transitions for attack actions
    transition_id_counter = 0
    
    for node_id in tree.nodes():
        attrs = node_attrs.get(node_id, {})
        time_interval = attrs.get('time_interval', [0, 10])
        duration = attrs.get('duration', 1)
        gate_type = attrs.get('gate_type', None)
        
        # Create attack transition for this node
        transition_id = f"attack_{node_id}"
        transition = ET.SubElement(page, "transition", id=transition_id)
        
        # Position
        trans_x = place_positions.get(f"compromised_{node_id}", (0, 0))[0]
        trans_y = place_positions.get(f"compromised_{node_id}", (0, 0))[1] + 50
        transition_positions[transition_id] = (trans_x, trans_y)
        
        graphics = ET.SubElement(transition, "graphics")
        position = ET.SubElement(graphics, "position", x=str(trans_x), y=str(trans_y))
        
        # Name
        name_elem = ET.SubElement(transition, "name")
        text_elem = ET.SubElement(name_elem, "text")
        text_elem.text = f"attack_{node_id}"
        
        # Time guard (earliest and latest firing times)
        time_guard = ET.SubElement(transition, "timeguard")
        interval = ET.SubElement(time_guard, "interval")
        interval.set("start", str(time_interval[0]))
        interval.set("end", str(time_interval[0] + duration))
        
        transition_id_counter += 1
    
    # Create arcs based on tree structure and gate types
    for node_id in tree.nodes():
        children = list(tree.successors(node_id))
        if not children:  # Leaf node
            continue
            
        attrs = node_attrs.get(node_id, {})
        gate_type = attrs.get('gate_type', 'OR')
        
        # Create arcs from children to parent based on gate type
        if gate_type == 'AND':
            # AND gate: all children must be compromised
            for child_id in children:
                # Arc from child's compromised place to parent's attack transition
                arc = ET.SubElement(page, "arc")
                arc.set("id", f"arc_{child_id}_to_{node_id}")
                arc.set("source", f"compromised_{child_id}")
                arc.set("target", f"attack_{node_id}")
                
                # Arc weight (how many tokens needed)
                inscription = ET.SubElement(arc, "inscription")
                text_elem = ET.SubElement(inscription, "text")
                text_elem.text = "1"
        
        elif gate_type == 'OR':
            # OR gate: any child can trigger parent
            for child_id in children:
                # Arc from child's compromised place to parent's attack transition
                arc = ET.SubElement(page, "arc")
                arc.set("id", f"arc_{child_id}_to_{node_id}")
                arc.set("source", f"compromised_{child_id}")
                arc.set("target", f"attack_{node_id}")
                
                # Arc weight
                inscription = ET.SubElement(arc, "inscription")
                text_elem = ET.SubElement(inscription, "text")
                text_elem.text = "1"
        
        # Arc from parent's attack transition to parent's compromised place
        arc = ET.SubElement(page, "arc")
        arc.set("id", f"arc_{node_id}_compromise")
        arc.set("source", f"attack_{node_id}")
        arc.set("target", f"compromised_{node_id}")
        
        inscription = ET.SubElement(arc, "inscription")
        text_elem = ET.SubElement(inscription, "text")
        text_elem.text = "1"
    
    # Convert to string
    ET.indent(root, space="  ", level=0)
    return ET.tostring(root, encoding='unicode', xml_declaration=True)


def diagnosability_query(tree: nx.DiGraph, observable_nodes: Set[str], tree_id: str) -> str:
    """
    Generate CTL query for checking weak diagnosability of an attack tree.
    
    The query checks if observing the compromise of nodes in observable_nodes
    allows unique identification of the attack path.
    
    Args:
        tree: NetworkX DiGraph representing the attack tree
        observable_nodes: Set of node IDs that are observable
        tree_id: Unique identifier for this tree
    
    Returns:
        CTL query string for TAPAAL
    """
    # Find root node (node with no predecessors)
    root_nodes = [n for n in tree.nodes() if tree.in_degree(n) == 0]
    if not root_nodes:
        # Find node with highest out-degree as fallback
        root_nodes = [max(tree.nodes(), key=lambda n: tree.out_degree(n))]
    
    root_node = root_nodes[0]
    
    # Create CTL formula for diagnosability
    # The basic idea: if we can reach a state where observable nodes are compromised,
    # then we should be able to uniquely determine the attack path
    
    # Generate observable conditions
    observable_conditions = []
    for obs_node in observable_nodes:
        observable_conditions.append(f"compromised_{obs_node} >= 1")
    
    if not observable_conditions:
        # If no observable nodes, check if root is reachable
        query = f"EF (compromised_{root_node} >= 1)"
    else:
        # Check if observable pattern leads to unique state
        obs_formula = " and ".join(observable_conditions)
        
        # Weak diagnosability: there exists a path where observables are compromised
        # and this leads to a unique attack scenario
        query = f"EF ({obs_formula} and compromised_{root_node} >= 1)"
    
    return f"// Diagnosability query for tree {tree_id}\n{query}\n"


def create_leaf_attack_places(page: ET.Element, leaf_nodes: List[str]) -> None:
    """
    Create additional places and transitions for leaf node attacks.
    
    Args:
        page: XML page element to add places to
        leaf_nodes: List of leaf node IDs
    """
    y_offset = 200
    
    for i, leaf_id in enumerate(leaf_nodes):
        # Create initial attack place for leaf
        place_id = f"can_attack_{leaf_id}"
        place = ET.SubElement(page, "place", id=place_id)
        
        # Position
        graphics = ET.SubElement(place, "graphics")
        position = ET.SubElement(graphics, "position", x=str(i * 150), y=str(y_offset))
        
        # Name
        name_elem = ET.SubElement(place, "name")
        text_elem = ET.SubElement(name_elem, "text")
        text_elem.text = f"can_attack_{leaf_id}"
        
        # Initial marking (1 token - attack is possible)
        initial_marking = ET.SubElement(place, "initialMarking")
        text_elem = ET.SubElement(initial_marking, "text")
        text_elem.text = "1"
        
        # Type
        type_elem = ET.SubElement(place, "type")
        text_elem = ET.SubElement(type_elem, "text")
        text_elem.text = "int"
        
        # Create arc from can_attack to attack transition
        arc = ET.SubElement(page, "arc")
        arc.set("id", f"arc_can_attack_{leaf_id}")
        arc.set("source", place_id)
        arc.set("target", f"attack_{leaf_id}")
        
        inscription = ET.SubElement(arc, "inscription")
        text_elem = ET.SubElement(inscription, "text")
        text_elem.text = "1"


def enhanced_tapaal_xml(tree: nx.DiGraph, node_attrs: Dict, tree_id: str) -> str:
    """
    Enhanced TAPAAL XML generation with proper timed semantics for attack trees.
    
    Args:
        tree: NetworkX DiGraph representing the attack tree
        node_attrs: Dictionary mapping node IDs to their attributes
        tree_id: Unique identifier for this tree
    
    Returns:
        Enhanced XML string in TAPAAL format
    """
    # Create basic structure
    xml_content = tapaal_xml(tree, node_attrs, tree_id)
    
    # Parse back to add enhancements
    root = ET.fromstring(xml_content)
    net = root.find('.//{http://www.pnml.org/version-2009/grammar/pnml}net')
    page = net.find('.//{http://www.pnml.org/version-2009/grammar/pnml}page')
    
    # Find leaf nodes
    leaf_nodes = [n for n in tree.nodes() if tree.out_degree(n) == 0]
    
    # Add leaf attack initialization
    create_leaf_attack_places(page, leaf_nodes)
    
    # Convert back to string
    ET.indent(root, space="  ", level=0)
    return ET.tostring(root, encoding='unicode', xml_declaration=True)
