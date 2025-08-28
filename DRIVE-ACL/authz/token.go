package authz

import (
	"fmt"
	"strconv"
	"strings"
)

type AuthorizationToken struct {
	UserID        int64   `json:"user_id"`
	AccountID     int64   `json:"account_id"`
	AccountName   string  `json:"account_name"`
	RoleID        int64   `json:"role_id"`
	AdvertiserIDs []int64 `json:"advertiser_ids"`
}

func collectIDs(node *Node) []string {
	if node == nil {
		return nil
	}
	var ids []string
	var dfs func(n *Node)
	dfs = func(n *Node) {
		if n.ID != "" && n.ID != "root" {
			ids = append(ids, fmt.Sprintf("%s:%s", n.Type, n.ID))
		}
		for _, c := range n.Children {
			dfs(c)
		}
	}
	dfs(node)
	return ids
}

// GetAuthorizationTokenDataForSSOUserId fetches partner, role, and advertiser mappings via SpiceDB
func GetAuthorizationTokenDataForSSOUserId(
	ssoUserId int64, partnerID *int64,
) (*AuthorizationToken, error) {
	fmt.Println("Generating authz token for SSO user:", ssoUserId, "partnerID filter:", partnerID)
	userType, userID := "users", fmt.Sprintf("%d", ssoUserId)

	// 1. Lookup partners accessible to the user
	partnerRoot := ListResourceHierarchy("partner", "view", userType, userID)
	partners := collectIDs(partnerRoot)
	fmt.Println("Accessible partners for user:", partners)
	if len(partners) == 0 {
		return nil, fmt.Errorf("no partners found for user %d", ssoUserId)
	}

	// 2. Select the partner (filtered if partnerID provided)
	var selectedPartner string
	if partnerID != nil {
		pid := fmt.Sprintf("partner:%d", *partnerID)
		for _, p := range partners {
			if p == pid {
				selectedPartner = p
				break
			}
		}
		if selectedPartner == "" {
			return nil, fmt.Errorf("user %d has no role under partner %d", ssoUserId, *partnerID)
		}
	} else {
		fmt.Println("No partnerID filter provided; defaulting to first partner:", partners[0])
		selectedPartner = partners[0]
	}

	// 3. Lookup roles for this user under the selected partner
	roleRoot := ListResourceHierarchy("roles", "user", userType, userID) // in future can be handled for multiple roles for that same user
	roles := collectIDs(roleRoot)
	if len(roles) == 0 {
		return nil, fmt.Errorf("no role found for user %d under %s", ssoUserId, selectedPartner)
	}
	roleID := strings.TrimPrefix(roles[0], "roles:")

	// 4. Lookup advertisers visible to this user
	advertiserRoot := ListResourceHierarchy("advertiser", "view", userType, userID)
	advertisers := collectIDs(advertiserRoot)

	var advertiserIDs []int64
	for _, adv := range advertisers {
		advIDStr := strings.TrimPrefix(adv, "advertiser:")
		if id, err := strconv.ParseInt(advIDStr, 10, 64); err == nil {
			advertiserIDs = append(advertiserIDs, id)
		}
	}

	// 5. Build token
	token := &AuthorizationToken{
		UserID:        ssoUserId,
		AccountID:     parsePartnerID(selectedPartner),
		AccountName:   lookupPartnerName(selectedPartner),
		RoleID:        parseRoleID(roleID),
		AdvertiserIDs: advertiserIDs,
	}
	return token, nil
}

func parsePartnerID(obj string) int64 {
	parts := strings.Split(obj, ":")
	if len(parts) == 2 {
		if id, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
			return id
		}
	}
	return 0
}

func parseRoleID(roleID string) int64 {
	id, _ := strconv.ParseInt(roleID, 10, 64)
	return id
}

func lookupPartnerName(partner string) string {
	// Fetch from SQL/Redis/config instead of SpiceDB
	return ""
}
