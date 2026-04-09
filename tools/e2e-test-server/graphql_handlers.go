// Package main provides main functionality for the proxy.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

// Simple in-memory data store for GraphQL
type User struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Age      int      `json:"age"`
	Location Location `json:"location"`
}

// Location represents a location.
type Location struct {
	City    string `json:"city"`
	Country string `json:"country"`
}

// Post represents a post.
type Post struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Content  string   `json:"content"`
	AuthorID string   `json:"authorId"`
	Tags     []string `json:"tags"`
}

var testUsers = []User{
	{
		ID:    "1",
		Name:  "Alice Johnson",
		Email: "alice@example.com",
		Age:   30,
		Location: Location{
			City:    "New York",
			Country: "USA",
		},
	},
	{
		ID:    "2",
		Name:  "Bob Smith",
		Email: "bob@example.com",
		Age:   25,
		Location: Location{
			City:    "London",
			Country: "UK",
		},
	},
}

var testPosts = []Post{
	{
		ID:       "1",
		Title:    "GraphQL Introduction",
		Content:  "GraphQL is a query language for APIs...",
		AuthorID: "1",
		Tags:     []string{"graphql", "api", "tutorial"},
	},
	{
		ID:       "2",
		Title:    "Testing Best Practices",
		Content:  "End-to-end testing ensures...",
		AuthorID: "2",
		Tags:     []string{"testing", "e2e"},
	},
}

func (s *Server) registerGraphQLHandlers(mux *http.ServeMux) {
	// GraphQL endpoint
	mux.HandleFunc("/graphql", s.handleGraphQL)
	
	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "service": "graphql"})
	})
	
	// Info endpoint
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		
		info := map[string]interface{}{
			"service": "GraphQL Test Server",
			"endpoints": map[string]string{
				"GET  /":         "This info",
				"GET  /health":   "Health check",
				"POST /graphql":  "GraphQL endpoint",
			},
			"queries": []string{
				"users",
				"user(id: ID)",
				"posts",
				"post(id: ID)",
			},
			"example": `{"query": "{ users { id name email } }"}`,
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
	})
}

func (s *Server) handleGraphQL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Query     string                 `json:"query"`
		Variables map[string]interface{} `json:"variables"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("GraphQL query: %s", req.Query)

	// Simple query parser (very basic, for testing only)
	response := s.executeGraphQLQuery(req.Query, req.Variables)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) executeGraphQLQuery(query string, variables map[string]interface{}) map[string]interface{} {
	// Normalize query
	query = strings.TrimSpace(query)
	query = strings.ReplaceAll(query, "\n", " ")
	query = strings.ReplaceAll(query, "\t", " ")

	// Very simple query parsing for testing
	response := map[string]interface{}{
		"data": nil,
	}

	// Check for users query
	if strings.Contains(query, "users") {
		response["data"] = map[string]interface{}{
			"users": testUsers,
		}
		return response
	}

	// Check for specific user query
	if strings.Contains(query, "user(") || strings.Contains(query, "user (") {
		// Extract ID from query (very simplistic)
		var userID string
		if strings.Contains(query, `id: "1"`) || strings.Contains(query, `id:"1"`) {
			userID = "1"
		} else if strings.Contains(query, `id: "2"`) || strings.Contains(query, `id:"2"`) {
			userID = "2"
		}

		for _, user := range testUsers {
			if user.ID == userID {
				response["data"] = map[string]interface{}{
					"user": user,
				}
				return response
			}
		}
	}

	// Check for posts query
	if strings.Contains(query, "posts") {
		response["data"] = map[string]interface{}{
			"posts": testPosts,
		}
		return response
	}

	// Check for specific post query
	if strings.Contains(query, "post(") || strings.Contains(query, "post (") {
		// Extract ID from query
		var postID string
		if strings.Contains(query, `id: "1"`) || strings.Contains(query, `id:"1"`) {
			postID = "1"
		} else if strings.Contains(query, `id: "2"`) || strings.Contains(query, `id:"2"`) {
			postID = "2"
		}

		for _, post := range testPosts {
			if post.ID == postID {
				response["data"] = map[string]interface{}{
					"post": post,
				}
				return response
			}
		}
	}

	// Default: return test data
	response["data"] = map[string]interface{}{
		"message": "Query processed",
		"timestamp": time.Now().Unix(),
	}

	return response
}

