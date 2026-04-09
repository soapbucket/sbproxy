// Package orchestration coordinates multi-step request processing workflows and action sequencing.
package orchestration

import (
	"fmt"
)

// DependencyGraph represents a directed acyclic graph of steps
type DependencyGraph struct {
	nodes map[string]*GraphNode
}

// GraphNode represents a node in the dependency graph
type GraphNode struct {
	step         Step
	dependencies []*GraphNode // Steps this node depends on
	dependents   []*GraphNode // Steps that depend on this node
	level        int          // Level in the graph (for parallel execution)
}

// buildDependencyGraph creates a dependency graph from steps
func buildDependencyGraph(steps []Step) (*DependencyGraph, error) {
	graph := &DependencyGraph{
		nodes: make(map[string]*GraphNode),
	}

	// Create nodes for all steps
	for _, step := range steps {
		graph.nodes[step.name] = &GraphNode{
			step:         step,
			dependencies: make([]*GraphNode, 0),
			dependents:   make([]*GraphNode, 0),
			level:        0,
		}
	}

	// Build edges (dependencies)
	for _, step := range steps {
		node := graph.nodes[step.name]
		
		for _, depName := range step.dependsOn {
			depNode, exists := graph.nodes[depName]
			if !exists {
				return nil, fmt.Errorf("step '%s' depends on unknown step '%s'", step.name, depName)
			}
			
			// Add dependency edge
			node.dependencies = append(node.dependencies, depNode)
			depNode.dependents = append(depNode.dependents, node)
		}
	}

	// Calculate levels for parallel execution (only if no cycles)
	// Skip level calculation if graph has cycles - will be caught by Validate()
	if !graph.hasCycle() {
		graph.calculateLevels()
	}

	return graph, nil
}

// hasCycle detects if the graph has a cycle using DFS
func (g *DependencyGraph) hasCycle() bool {
	visited := make(map[string]bool)
	recursionStack := make(map[string]bool)

	for name := range g.nodes {
		if g.hasCycleDFS(name, visited, recursionStack) {
			return true
		}
	}

	return false
}

// hasCycleDFS performs DFS to detect cycles
func (g *DependencyGraph) hasCycleDFS(nodeName string, visited, recursionStack map[string]bool) bool {
	// Mark as visited and on current recursion stack
	visited[nodeName] = true
	recursionStack[nodeName] = true

	node, exists := g.nodes[nodeName]
	if !exists {
		// Node doesn't exist, no cycle from this path
		recursionStack[nodeName] = false
		return false
	}

	// Check all dependencies
	for _, dep := range node.dependencies {
		depName := dep.step.name
		
		// If not visited, recurse
		if !visited[depName] {
			if g.hasCycleDFS(depName, visited, recursionStack) {
				return true
			}
		} else if recursionStack[depName] {
			// Already on recursion stack - found a cycle!
			return true
		}
		// else: visited but not on stack - already processed, skip
	}

	// Remove from recursion stack before returning
	recursionStack[nodeName] = false
	return false
}

// topologicalSort returns steps in topological order (dependencies first)
func (g *DependencyGraph) topologicalSort() []Step {
	visited := make(map[string]bool)
	stack := []Step{}

	// Visit each node
	for name := range g.nodes {
		if !visited[name] {
			g.topologicalSortDFS(name, visited, &stack)
		}
	}

	// Stack is already in correct order (DFS post-order traversal)
	// Dependencies are visited first, so they appear earlier in the stack
	return stack
}

// topologicalSortDFS performs DFS for topological sort
func (g *DependencyGraph) topologicalSortDFS(nodeName string, visited map[string]bool, stack *[]Step) {
	visited[nodeName] = true

	node := g.nodes[nodeName]
	
	// Visit all dependencies first
	for _, dep := range node.dependencies {
		if !visited[dep.step.name] {
			g.topologicalSortDFS(dep.step.name, visited, stack)
		}
	}

	// Add this node to stack
	*stack = append(*stack, node.step)
}

// calculateLevels calculates the level of each node for parallel execution
// Level 0: nodes with no dependencies
// Level N: nodes whose dependencies are all in levels < N
func (g *DependencyGraph) calculateLevels() {
	// Initialize all levels to 0
	for _, node := range g.nodes {
		node.level = 0
	}

	// Calculate levels iteratively with max iteration limit to prevent infinite loops
	maxIterations := len(g.nodes) * 2 // Should converge in at most N iterations
	iterations := 0
	changed := true
	
	for changed && iterations < maxIterations {
		iterations++
		changed = false
		
		for _, node := range g.nodes {
			// Find max level of dependencies
			maxDepLevel := -1
			for _, dep := range node.dependencies {
				if dep.level > maxDepLevel {
					maxDepLevel = dep.level
				}
			}

			// This node's level is one more than max dependency level
			newLevel := maxDepLevel + 1
			if newLevel != node.level {
				node.level = newLevel
				changed = true
			}
		}
	}
	
	// If we hit max iterations, there might be a cycle (shouldn't happen if hasCycle was checked)
	if iterations >= maxIterations {
		// Log warning but don't fail - cycles should be caught by Validate()
		// Just set all levels to 0 as fallback
		for _, node := range g.nodes {
			node.level = 0
		}
	}
}

// getLevels returns steps grouped by level for parallel execution
func (g *DependencyGraph) getLevels() [][]Step {
	// Find max level
	maxLevel := 0
	for _, node := range g.nodes {
		if node.level > maxLevel {
			maxLevel = node.level
		}
	}

	// Group steps by level
	levels := make([][]Step, maxLevel+1)
	for _, node := range g.nodes {
		levels[node.level] = append(levels[node.level], node.step)
	}

	return levels
}

// GetExecutionOrder returns the execution order for sequential execution
func (g *DependencyGraph) GetExecutionOrder() []string {
	steps := g.topologicalSort()
	names := make([]string, len(steps))
	for i, step := range steps {
		names[i] = step.name
	}
	return names
}

// Validate validates the dependency graph
func (g *DependencyGraph) Validate() error {
	// Check for cycles
	if g.hasCycle() {
		return fmt.Errorf("circular dependency detected")
	}

	// Check that all dependencies exist
	for name, node := range g.nodes {
		for _, depName := range node.step.dependsOn {
			if _, exists := g.nodes[depName]; !exists {
				return fmt.Errorf("step '%s' depends on unknown step '%s'", name, depName)
			}
		}
	}

	return nil
}

