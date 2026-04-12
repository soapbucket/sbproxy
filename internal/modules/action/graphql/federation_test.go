package graphql

import (
	"testing"
)

func TestFederationRouterCreation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     FederationConfig
		wantErr bool
	}{
		{
			name: "valid config with two subgraphs",
			cfg: FederationConfig{
				Enabled: true,
				Subgraphs: []SubgraphConfig{
					{Name: "products", URL: "http://products:4001/graphql"},
					{Name: "reviews", URL: "http://reviews:4002/graphql"},
				},
			},
			wantErr: false,
		},
		{
			name: "disabled federation",
			cfg: FederationConfig{
				Enabled: false,
			},
			wantErr: true,
		},
		{
			name: "no subgraphs",
			cfg: FederationConfig{
				Enabled:   true,
				Subgraphs: []SubgraphConfig{},
			},
			wantErr: true,
		},
		{
			name: "subgraph missing name",
			cfg: FederationConfig{
				Enabled: true,
				Subgraphs: []SubgraphConfig{
					{URL: "http://products:4001/graphql"},
				},
			},
			wantErr: true,
		},
		{
			name: "subgraph missing URL",
			cfg: FederationConfig{
				Enabled: true,
				Subgraphs: []SubgraphConfig{
					{Name: "products"},
				},
			},
			wantErr: true,
		},
		{
			name: "subgraph with headers",
			cfg: FederationConfig{
				Enabled: true,
				Subgraphs: []SubgraphConfig{
					{
						Name: "products",
						URL:  "http://products:4001/graphql",
						Headers: map[string]string{
							"Authorization": "Bearer token123",
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, err := NewFederationRouter(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFederationRouter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && router == nil {
				t.Error("NewFederationRouter() returned nil router without error")
			}
		})
	}
}

func TestFederationRouterGetSubgraph(t *testing.T) {
	router, err := NewFederationRouter(FederationConfig{
		Enabled: true,
		Subgraphs: []SubgraphConfig{
			{Name: "products", URL: "http://products:4001/graphql"},
			{Name: "reviews", URL: "http://reviews:4002/graphql"},
		},
	})
	if err != nil {
		t.Fatalf("NewFederationRouter() error = %v", err)
	}

	t.Run("existing subgraph", func(t *testing.T) {
		sg, ok := router.GetSubgraph("products")
		if !ok {
			t.Error("GetSubgraph(products) returned false")
		}
		if sg.Name != "products" {
			t.Errorf("subgraph name = %q, want products", sg.Name)
		}
		if sg.URL != "http://products:4001/graphql" {
			t.Errorf("subgraph URL = %q, want http://products:4001/graphql", sg.URL)
		}
	})

	t.Run("non-existing subgraph", func(t *testing.T) {
		_, ok := router.GetSubgraph("nonexistent")
		if ok {
			t.Error("GetSubgraph(nonexistent) should return false")
		}
	})
}

func TestFederationRouterRegisterType(t *testing.T) {
	router, err := NewFederationRouter(FederationConfig{
		Enabled: true,
		Subgraphs: []SubgraphConfig{
			{Name: "products", URL: "http://products:4001/graphql"},
		},
	})
	if err != nil {
		t.Fatalf("NewFederationRouter() error = %v", err)
	}

	t.Run("register valid type", func(t *testing.T) {
		err := router.RegisterType("products", &FederatedType{
			Name:      "Product",
			KeyFields: []string{"id"},
		})
		if err != nil {
			t.Errorf("RegisterType() error = %v", err)
		}

		sg, _ := router.GetSubgraph("products")
		ft, ok := sg.Types["Product"]
		if !ok {
			t.Fatal("type Product not found in subgraph")
		}
		if ft.Subgraph != "products" {
			t.Errorf("type subgraph = %q, want products", ft.Subgraph)
		}
		if len(ft.KeyFields) != 1 || ft.KeyFields[0] != "id" {
			t.Errorf("type key fields = %v, want [id]", ft.KeyFields)
		}
	})

	t.Run("register to nonexistent subgraph", func(t *testing.T) {
		err := router.RegisterType("nonexistent", &FederatedType{
			Name:      "Product",
			KeyFields: []string{"id"},
		})
		if err == nil {
			t.Error("RegisterType() should fail for nonexistent subgraph")
		}
	})

	t.Run("register type with empty name", func(t *testing.T) {
		err := router.RegisterType("products", &FederatedType{
			KeyFields: []string{"id"},
		})
		if err == nil {
			t.Error("RegisterType() should fail for empty type name")
		}
	})
}

func TestFederationRouterFindTypeOwner(t *testing.T) {
	router, err := NewFederationRouter(FederationConfig{
		Enabled: true,
		Subgraphs: []SubgraphConfig{
			{Name: "products", URL: "http://products:4001/graphql"},
			{Name: "reviews", URL: "http://reviews:4002/graphql"},
		},
	})
	if err != nil {
		t.Fatalf("NewFederationRouter() error = %v", err)
	}

	err = router.RegisterType("products", &FederatedType{Name: "Product", KeyFields: []string{"id"}})
	if err != nil {
		t.Fatalf("RegisterType() error = %v", err)
	}
	err = router.RegisterType("reviews", &FederatedType{Name: "Review", KeyFields: []string{"id"}})
	if err != nil {
		t.Fatalf("RegisterType() error = %v", err)
	}

	t.Run("find Product owner", func(t *testing.T) {
		sg, ok := router.FindTypeOwner("Product")
		if !ok {
			t.Fatal("FindTypeOwner(Product) returned false")
		}
		if sg.Name != "products" {
			t.Errorf("owner = %q, want products", sg.Name)
		}
	})

	t.Run("find Review owner", func(t *testing.T) {
		sg, ok := router.FindTypeOwner("Review")
		if !ok {
			t.Fatal("FindTypeOwner(Review) returned false")
		}
		if sg.Name != "reviews" {
			t.Errorf("owner = %q, want reviews", sg.Name)
		}
	})

	t.Run("type not found", func(t *testing.T) {
		_, ok := router.FindTypeOwner("NonExistent")
		if ok {
			t.Error("FindTypeOwner(NonExistent) should return false")
		}
	})
}

func TestFederationSchemaParser(t *testing.T) {
	tests := []struct {
		name       string
		schema     string
		wantTypes  int
		wantFields map[string][]string
	}{
		{
			name: "single type with single key",
			schema: `type Product @key(fields: "id") {
				id: ID!
				name: String
			}`,
			wantTypes: 1,
			wantFields: map[string][]string{
				"Product": {"id"},
			},
		},
		{
			name: "type with compound key",
			schema: `type Review @key(fields: "userId productId") {
				userId: ID!
				productId: ID!
				body: String
			}`,
			wantTypes: 1,
			wantFields: map[string][]string{
				"Review": {"userId", "productId"},
			},
		},
		{
			name: "multiple types",
			schema: `type Product @key(fields: "id") {
				id: ID!
				name: String
			}
			type User @key(fields: "email") {
				email: String!
				name: String
			}`,
			wantTypes: 2,
			wantFields: map[string][]string{
				"Product": {"id"},
				"User":    {"email"},
			},
		},
		{
			name: "type without key directive",
			schema: `type Product {
				id: ID!
				name: String
			}`,
			wantTypes: 0,
		},
		{
			name:      "empty schema",
			schema:    "",
			wantTypes: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := FederationConfig{
				Enabled: true,
				Subgraphs: []SubgraphConfig{
					{Name: "test", URL: "http://test:4001/graphql", Schema: tt.schema},
				},
			}

			router, err := NewFederationRouter(cfg)
			if err != nil {
				t.Fatalf("NewFederationRouter() error = %v", err)
			}

			sg, ok := router.GetSubgraph("test")
			if !ok {
				t.Fatal("subgraph test not found")
			}

			if len(sg.Types) != tt.wantTypes {
				t.Errorf("got %d types, want %d", len(sg.Types), tt.wantTypes)
			}

			for typeName, wantFields := range tt.wantFields {
				ft, ok := sg.Types[typeName]
				if !ok {
					t.Errorf("type %q not found", typeName)
					continue
				}
				if len(ft.KeyFields) != len(wantFields) {
					t.Errorf("type %q: got %d key fields, want %d", typeName, len(ft.KeyFields), len(wantFields))
					continue
				}
				for i, f := range wantFields {
					if ft.KeyFields[i] != f {
						t.Errorf("type %q key field %d = %q, want %q", typeName, i, ft.KeyFields[i], f)
					}
				}
			}
		})
	}
}

func TestFederationGetSubgraphs(t *testing.T) {
	router, err := NewFederationRouter(FederationConfig{
		Enabled: true,
		Subgraphs: []SubgraphConfig{
			{Name: "products", URL: "http://products:4001/graphql"},
			{Name: "reviews", URL: "http://reviews:4002/graphql"},
		},
	})
	if err != nil {
		t.Fatalf("NewFederationRouter() error = %v", err)
	}

	subgraphs := router.GetSubgraphs()
	if len(subgraphs) != 2 {
		t.Errorf("got %d subgraphs, want 2", len(subgraphs))
	}
	if _, ok := subgraphs["products"]; !ok {
		t.Error("subgraph products not found")
	}
	if _, ok := subgraphs["reviews"]; !ok {
		t.Error("subgraph reviews not found")
	}
}
