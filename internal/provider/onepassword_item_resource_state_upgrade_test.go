package provider

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/1Password/terraform-provider-onepassword/v3/internal/onepassword/model"
)

// TestAccItemResource_StateUpgrade_LettersRemoved guards the migration this
// file adds for state written by the last pre-3.0 release, which still had
// password_recipe.letters in its schema. It creates an item with that
// release (so "letters" ends up recorded in state) and then re-plans/applies
// it with the current provider, asserting that succeeds cleanly.
func TestAccItemResource_StateUpgrade_LettersRemoved(t *testing.T) {
	expectedItem := generatePasswordItem()
	expectedVault := model.Vault{
		ID:   expectedItem.VaultID,
		Name: "VaultName",
	}

	testServer := setupTestServer(expectedItem, expectedVault, t)
	defer testServer.Close()

	config := fmt.Sprintf(`
data "onepassword_vault" "acceptance-tests" {
  uuid = "%s"
}
resource "onepassword_item" "test-migration" {
  vault    = data.onepassword_vault.acceptance-tests.uuid
  title    = "%s"
  category = "%s"
  username = "%s"
  password_recipe {}
}`, expectedItem.VaultID, expectedItem.Title, strings.ToLower(string(expectedItem.Category)), expectedItem.Fields[0].Value)

	resource.UnitTest(t, resource.TestCase{
		Steps: []resource.TestStep{
			{
				// Create the item with the last pre-3.0 release: its schema
				// still has password_recipe.letters, so it gets written into
				// state.
				ExternalProviders: map[string]resource.ExternalProvider{
					"onepassword": {
						VersionConstraint: "2.2.1",
						Source:            "1Password/onepassword",
					},
				},
				// 2.2.1 predates the connect_url/connect_token rename.
				Config: testAccProviderConfigLegacy(testServer.URL) + config,
			},
			{
				// Re-apply that same state with the current, in-development
				// provider, which no longer has "letters" in its schema.
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Config:                   testAccProviderConfig(testServer.URL) + config,
			},
		},
	})
}

func testAccProviderConfigLegacy(url string) string {
	return fmt.Sprintf(`
	  provider "onepassword" {
		url   = "%s"
		token = "<PASSWORD>"
	  }`, url)
}
