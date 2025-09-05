package authz

import (
	"fmt"
	"strings"
)

// Convert JSON → SpiceDB relation strings
func Translate(jsonData map[string]interface{}) []string {
	var rels []string

	// --- Roles ---
	if roles, ok := jsonData["roles"].(map[string]interface{}); ok {
		fmt.Println("Processing roles...", roles)
		for role, v := range roles {
			fmt.Println("Processing role:", role, v)
			if roleMap, ok := v.(map[string]interface{}); ok {
				for a, user := range toStrSlice(roleMap["users"]) {
					fmt.Println("users:", user, a)
					fmt.Println("Adding role user:", role, user)
					rels = append(rels, fmt.Sprintf("roles:%s#user@users:%s", role, user))
				}
				for _, scope := range toStrSlice(roleMap["scopes"]) {
					// scope must be one of: partner:ID | advertiser:ID | publisher:ID | feature:ID
					if subj, ok := parseScopedSubject(scope, []string{"partner", "advertiser", "publisher", "feature", "page"}); ok {
						rels = append(rels, fmt.Sprintf("roles:%s#scope@%s", role, subj))
					}
				}
			}
		}
	}

	// --- Superroot ---
	if sr, ok := jsonData["superroot"].(map[string]interface{}); ok {
		for root, cfg := range sr {
			if cfgMap, ok := cfg.(map[string]interface{}); ok {
				for _, sa := range toStrSlice(cfgMap["superadmin"]) {
					rels = append(rels, fmt.Sprintf("superroot:%s#superadmin@users:%s", root, sa))
				}
				for _, sa := range toStrSlice(cfgMap["globaluser"]) {
					rels = append(rels, fmt.Sprintf("superroot:%s#globaluser@globaluser:%s", root, sa))
				}
			}
		}
	}

	if sr, ok := jsonData["globaluser"].(map[string]interface{}); ok {
		for root, cfg := range sr {
			if cfgMap, ok := cfg.(map[string]interface{}); ok {
				for _, sa := range toStrSlice(cfgMap["globaladmin"]) {
					rels = append(rels, fmt.Sprintf("globaluser:%s#globaladmin@users:%s", root, sa))
				}
			}
		}
	}

	// --- APIs ---
	if apis, ok := jsonData["apis"].(map[string]interface{}); ok {
		for aname, v := range apis {
			if aMap, ok := v.(map[string]interface{}); ok {
				// parent → must be a feature
				if parent := getString(aMap["parent"]); parent != "" {
					if subj, ok := parseScopedSubject(parent, []string{"feature"}); ok {
						rels = append(rels, fmt.Sprintf("api:%s#parent@%s", aname, subj))
					}
				}
				// roles
				for _, r := range toStrSlice(aMap["roles"]) {
					rels = append(rels, fmt.Sprintf("api:%s#role@roles:%s", aname, r))
				}
				// users
				for _, u := range toStrSlice(aMap["users"]) {
					rels = append(rels, fmt.Sprintf("api:%s#user@users:%s", aname, u))
				}
				// denied users
				for _, d := range toStrSlice(aMap["denied_users"]) {
					rels = append(rels, fmt.Sprintf("api:%s#denied_user@users:%s", aname, d))
				}
			}
		}
	}

	// --- Pages ---
	if pages, ok := jsonData["pages"].(map[string]interface{}); ok {
		for pname, v := range pages {
			if pMap, ok := v.(map[string]interface{}); ok {
				// root → superroot
				if root := getString(pMap["root"]); root != "" {
					rels = append(rels, fmt.Sprintf("page:%s#root@superroot:%s", pname, root))
				}
				// users
				for _, u := range toStrSlice(pMap["users"]) {
					rels = append(rels, fmt.Sprintf("page:%s#user@users:%s", pname, u))
				}
				// roles
				for _, r := range toStrSlice(pMap["roles"]) {
					rels = append(rels, fmt.Sprintf("page:%s#role@roles:%s", pname, r))
				}
				// public
				if hasWildcard(pMap["public"]) {
					rels = append(rels, fmt.Sprintf("page:%s#public@users:*", pname))
				}
				// denied
				for _, d := range toStrSlice(pMap["denied_users"]) {
					rels = append(rels, fmt.Sprintf("page:%s#denied_user@users:%s", pname, d))
				}
				// features attached directly to page
				for _, f := range toStrSlice(pMap["features"]) {
					if subj, ok := parseScopedSubject(f, []string{"feature"}); ok {
						rels = append(rels, fmt.Sprintf("page:%s#feature@%s", pname, subj))
					}
				}
			}
		}
	}

	// --- Partners ---
	// --- Partners ---
	if partners, ok := jsonData["partners"].(map[string]interface{}); ok {
		for pname, v := range partners {
			if pMap, ok := v.(map[string]interface{}); ok {
				// root → superroot
				if root := getString(pMap["root"]); root != "" {
					rels = append(rels, fmt.Sprintf("partner:%s#root@superroot:%s", pname, root))
				}
				// users
				for _, u := range toStrSlice(pMap["users"]) {
					rels = append(rels, fmt.Sprintf("partner:%s#user@users:%s", pname, u))
				}
				// roles
				for _, r := range toStrSlice(pMap["roles"]) {
					rels = append(rels, fmt.Sprintf("partner:%s#role@roles:%s", pname, r))
				}
				// public wildcard
				if hasWildcard(pMap["public"]) {
					rels = append(rels, fmt.Sprintf("partner:%s#public@users:*", pname))
				}
				// 🔥 NEW: global wildcard
				if hasWildcard(pMap["global"]) {
					rels = append(rels, fmt.Sprintf("partner:%s#global@globaluser:*", pname))
				}
				// denied users
				for _, d := range toStrSlice(pMap["denied_users"]) {
					rels = append(rels, fmt.Sprintf("partner:%s#denied_user@users:%s", pname, d))
				}
			}
		}
	}

	// --- Advertisers ---
	if advs, ok := jsonData["advertisers"].(map[string]interface{}); ok {
		for aname, v := range advs {
			if aMap, ok := v.(map[string]interface{}); ok {
				// root → superroot
				if root := getString(aMap["root"]); root != "" {
					rels = append(rels, fmt.Sprintf("advertiser:%s#root@superroot:%s", aname, root))
				}
				// parent partner
				if parent := getString(aMap["parent"]); parent != "" {
					if subj, ok := parseScopedSubject(parent, []string{"partner"}); ok {
						rels = append(rels, fmt.Sprintf("advertiser:%s#parent@%s", aname, subj))
					}
				}
				// users / roles
				for _, r := range toStrSlice(aMap["roles"]) {
					rels = append(rels, fmt.Sprintf("advertiser:%s#role@roles:%s", aname, r))
				}
				for _, u := range toStrSlice(aMap["users"]) {
					rels = append(rels, fmt.Sprintf("advertiser:%s#user@users:%s", aname, u))
				}
				// public / denied
				if hasWildcard(aMap["public"]) {
					rels = append(rels, fmt.Sprintf("advertiser:%s#public@users:*", aname))
				}
				for _, d := range toStrSlice(aMap["denied_users"]) {
					rels = append(rels, fmt.Sprintf("advertiser:%s#denied_user@users:%s", aname, d))
				}
			}
		}
	}

	// --- Publishers ---
	if pubs, ok := jsonData["publishers"].(map[string]interface{}); ok {
		for pname, v := range pubs {
			if pMap, ok := v.(map[string]interface{}); ok {
				// root → superroot
				if root := getString(pMap["root"]); root != "" {
					rels = append(rels, fmt.Sprintf("publisher:%s#root@superroot:%s", pname, root))
				}
				// parent partner
				if parent := getString(pMap["parent"]); parent != "" {
					if subj, ok := parseScopedSubject(parent, []string{"partner"}); ok {
						rels = append(rels, fmt.Sprintf("publisher:%s#parent@%s", pname, subj))
					}
				}
				// users / roles
				for _, r := range toStrSlice(pMap["roles"]) {
					rels = append(rels, fmt.Sprintf("publisher:%s#role@roles:%s", pname, r))
				}
				for _, u := range toStrSlice(pMap["users"]) {
					rels = append(rels, fmt.Sprintf("publisher:%s#user@users:%s", pname, u))
				}
				// public / denied
				if hasWildcard(pMap["public"]) {
					rels = append(rels, fmt.Sprintf("publisher:%s#public@users:*", pname))
				}
				for _, d := range toStrSlice(pMap["denied_users"]) {
					rels = append(rels, fmt.Sprintf("publisher:%s#denied_user@users:%s", pname, d))
				}
			}
		}
	}

	// --- Features (recursive + top-level parent/root) ---
	if features, ok := jsonData["features"].(map[string]interface{}); ok {
		for fname, v := range features {
			rels = append(rels, processFeature(fname, v, "")...)
		}
	}

	return dedupStrings(flatten(rels))
}

// Recursive feature processing
func processFeature(fname string, raw interface{}, parentFeature string) []string {
	var rels []string
	fmap, ok := raw.(map[string]interface{})
	if !ok {
		return rels
	}

	// If nested under another feature, set parent to that feature
	if parentFeature != "" {
		rels = append(rels, fmt.Sprintf("feature:%s#parent@feature:%s", fname, parentFeature))
	}

	// Optional explicit root for feature → superroot
	if root := getString(fmap["root"]); root != "" {
		rels = append(rels, fmt.Sprintf("feature:%s#root@superroot:%s", fname, root))
	}

	// Optional explicit top-level parent for feature (advertiser|publisher|feature)
	// Accepts string or []string; each value like "advertiser:adv1", "publisher:pub1", or "feature:parent"
	for _, p := range toStrSlice(fmap["parent"]) {
		if subj, ok := parseScopedSubject(p, []string{"advertiser", "publisher", "feature", "partner", "page"}); ok {
			rels = append(rels, fmt.Sprintf("feature:%s#parent@%s", fname, subj))
		}
	}

	// users / roles
	for _, u := range toStrSlice(fmap["users"]) {
		rels = append(rels, fmt.Sprintf("feature:%s#user@users:%s", fname, u))
	}
	for _, r := range toStrSlice(fmap["roles"]) {
		rels = append(rels, fmt.Sprintf("feature:%s#role@roles:%s", fname, r))
	}

	// public / denied
	if hasWildcard(fmap["public"]) {
		rels = append(rels, fmt.Sprintf("feature:%s#public@users:*", fname))
	}
	for _, d := range toStrSlice(fmap["denied_users"]) {
		rels = append(rels, fmt.Sprintf("feature:%s#denied_user@users:%s", fname, d))
	}

	// children
	if children, ok := fmap["children"].(map[string]interface{}); ok {
		for cname, cv := range children {
			rels = append(rels, processFeature(cname, cv, fname)...)
		}
	}

	return rels
}

// ----------------- helpers -----------------

func toStrSlice(v interface{}) []string {
	var out []string
	switch t := v.(type) {
	case string:
		if t != "" {
			out = append(out, t)
		}
	case []interface{}:
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func getString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// hasWildcard interprets public flags as: true | "*" | ["*"]
func hasWildcard(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "*"
	case []interface{}:
		for _, e := range t {
			if s, ok := e.(string); ok && s == "*" {
				return true
			}
		}
	}
	return false
}

// parseScopedSubject ensures the subject has an allowed type prefix.
func parseScopedSubject(s string, allowed []string) (string, bool) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", false
	}
	typ, id := parts[0], parts[1]
	for _, a := range allowed {
		if typ == a && id != "" {
			return fmt.Sprintf("%s:%s", typ, id), true
		}
	}
	return "", false
}

func dedupStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func flatten(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
