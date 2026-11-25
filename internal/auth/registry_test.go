package auth

import "testing"

func TestRegistryScopes(t *testing.T) {
	g, err := ParseGrant("operator@production/team-a+registry:team-a+registry:shared-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Scopes) != 3 || !g.Scopes[1].Registry() || g.Scopes[2].Project != "shared-*" {
		t.Fatalf("%+v", g)
	}
	if got := g.String(); got != "operator@production/team-a+registry:team-a+registry:shared-*" {
		t.Errorf("String: %s", got)
	}
	for _, bad := range []string{"viewer@registry:", "viewer@registry:Bad Name", "viewer@registry:a/b"} {
		if _, err := ParseGrant(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	u := NewUser("ci", []Grant{g})
	if u.RoleInProject("team-a") != Operator || u.RoleInProject("shared-tools") != Operator || u.RoleInProject("team-b") != 0 {
		t.Error("RoleInProject")
	}
	// A cluster's scope does not reach the registry, nor the registry's a cluster.
	clusterOnly := NewUser("ops", []Grant{{Role: Admin, Scopes: []Scope{{Cluster: "*", Namespace: "*"}}}})
	if clusterOnly.RoleInProject("team-a") != 0 || clusterOnly.RegistryRole() != 0 || clusterOnly.RegistryAdmin() {
		t.Error("a cluster admin reaches the registry")
	}
	registryOnly := NewUser("robot", []Grant{{Role: Admin, Scopes: []Scope{{Project: "*"}}}})
	if registryOnly.ClusterRole() != 0 || registryOnly.Everywhere() != 0 || registryOnly.RoleIn("production", "team-a") != 0 ||
		registryOnly.RoleSomewhere("production") != 0 || !registryOnly.RegistryAdmin() || registryOnly.Role != Admin {
		t.Errorf("a registry admin: cluster role %v, everywhere %v", registryOnly.ClusterRole(), registryOnly.Everywhere())
	}
	if u.ClusterRole() != Operator || u.RegistryRole() != Operator || u.RegistryAdmin() {
		t.Error("mixed grant")
	}
	// No scope is everywhere: every cluster and every project.
	all := NewUser("admin", []Grant{{Role: Admin}})
	if !all.RegistryAdmin() || all.RoleInProject("x") != Admin || all.ClusterRole() != Admin {
		t.Error("an admin everywhere")
	}
	projectAdmin := NewUser("lead", []Grant{{Role: Admin, Scopes: []Scope{{Project: "team-a"}}}})
	if projectAdmin.RegistryAdmin() || projectAdmin.RoleInProject("team-a") != Admin {
		t.Error("a project's admin is not the registry's")
	}
}
