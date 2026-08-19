package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Two attributes were removed from this resource's schema without a
// corresponding schema Version bump: password_recipe.letters (removed in
// v3.0.0, letters are now always generated) and section.field.purpose
// (removed for list-based section fields shortly after). Neither removal
// registered an UpgradeState entry, so any state instance that still has
// one of those keys - however it got there - has no explicit migration
// path; whether that manifests as a hard decode error depends on the
// Terraform/OpenTofu version doing the decoding, since decode strictness
// for unrecognized attributes on nested blocks isn't identical across
// versions we tested.
//
// This bumps the schema to Version 1 and registers a version-0 upgrader so
// state written under Version 0 - which covers every release up to and
// including the current one - is routed through PriorSchemaV0, where
// "letters" and "purpose" are read and dropped rather than left for Core to
// reject or silently ignore. This is a defensive fix: we could not
// reproduce a real-world failure caused by these two removals specifically,
// but leaving a schema change unversioned is incorrect regardless, and this
// closes the gap before it causes one.

// PasswordRecipeModelV0 mirrors PasswordRecipeModel plus the removed
// "letters" attribute.
type PasswordRecipeModelV0 struct {
	Length  types.Int64 `tfsdk:"length"`
	Digits  types.Bool  `tfsdk:"digits"`
	Symbols types.Bool  `tfsdk:"symbols"`
	Letters types.Bool  `tfsdk:"letters"`
}

// OnePasswordItemResourceFieldModelV0 mirrors OnePasswordItemResourceFieldModel
// plus the removed "purpose" attribute.
type OnePasswordItemResourceFieldModelV0 struct {
	ID      types.String            `tfsdk:"id"`
	Label   types.String            `tfsdk:"label"`
	Purpose types.String            `tfsdk:"purpose"`
	Type    types.String            `tfsdk:"type"`
	Value   types.String            `tfsdk:"value"`
	Recipe  []PasswordRecipeModelV0 `tfsdk:"password_recipe"`
}

// OnePasswordItemResourceSectionListModelV0 mirrors
// OnePasswordItemResourceSectionListModel, carrying the V0 field model.
type OnePasswordItemResourceSectionListModelV0 struct {
	ID        types.String                          `tfsdk:"id"`
	Label     types.String                          `tfsdk:"label"`
	FieldList []OnePasswordItemResourceFieldModelV0 `tfsdk:"field"`
}

// OnePasswordItemResourceModelV0 mirrors OnePasswordItemResourceModel as it
// existed at schema version 0. section_map/field_map are unaffected - that
// attribute was only added after both "letters" and "purpose" had already
// been removed, so it never had either and is reused as-is.
type OnePasswordItemResourceModelV0 struct {
	ID                 types.String                                      `tfsdk:"id"`
	UUID               types.String                                      `tfsdk:"uuid"`
	Vault              types.String                                      `tfsdk:"vault"`
	Category           types.String                                      `tfsdk:"category"`
	Title              types.String                                      `tfsdk:"title"`
	URL                types.String                                      `tfsdk:"url"`
	Hostname           types.String                                      `tfsdk:"hostname"`
	Database           types.String                                      `tfsdk:"database"`
	Port               types.String                                      `tfsdk:"port"`
	Type               types.String                                      `tfsdk:"type"`
	Tags               types.List                                        `tfsdk:"tags"`
	Username           types.String                                      `tfsdk:"username"`
	Password           types.String                                      `tfsdk:"password"`
	PasswordWO         types.String                                      `tfsdk:"password_wo"`
	PasswordWOVersion  types.Int64                                       `tfsdk:"password_wo_version"`
	NoteValue          types.String                                      `tfsdk:"note_value"`
	NoteValueWO        types.String                                      `tfsdk:"note_value_wo"`
	NoteValueWOVersion types.Int64                                       `tfsdk:"note_value_wo_version"`
	SectionList        []OnePasswordItemResourceSectionListModelV0       `tfsdk:"section"`
	SectionMap         map[string]OnePasswordItemResourceSectionMapModel `tfsdk:"section_map"`
	Recipe             []PasswordRecipeModelV0                           `tfsdk:"password_recipe"`
}

// UpgradeState registers the migration for state written before this
// resource tracked a schema Version.
func (r *OnePasswordItemResource) UpgradeState(ctx context.Context) map[int64]resource.StateUpgrader {
	return map[int64]resource.StateUpgrader{
		0: {
			PriorSchema:   itemResourceSchemaV0(),
			StateUpgrader: upgradeItemStateV0,
		},
	}
}

func itemResourceSchemaV0() *schema.Schema {
	passwordRecipeBlockSchemaV0 := schema.ListNestedBlock{
		MarkdownDescription: passwordRecipeDescription,
		Validators: []validator.List{
			listvalidator.SizeAtMost(1),
		},
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"length": schema.Int64Attribute{
					MarkdownDescription: passwordLengthDescription,
					Optional:            true,
					Computed:            true,
					Default:             int64default.StaticInt64(32),
					Validators: []validator.Int64{
						int64validator.Between(1, 64),
					},
				},
				"digits": schema.BoolAttribute{
					MarkdownDescription: passwordDigitsDescription,
					Optional:            true,
					Computed:            true,
					Default:             booldefault.StaticBool(true),
				},
				"symbols": schema.BoolAttribute{
					MarkdownDescription: passwordSymbolsDescription,
					Optional:            true,
					Computed:            true,
					Default:             booldefault.StaticBool(true),
				},
				// Removed in v3.0.0 (letters are now always generated) - kept
				// here only so old state still decodes.
				"letters": schema.BoolAttribute{
					MarkdownDescription: "Deprecated - letters are always included in generated passwords.",
					Optional:            true,
					Computed:            true,
					Default:             booldefault.StaticBool(true),
				},
			},
		},
	}

	sectionNestedObjectSchemaForMapV0 := schema.NestedAttributeObject{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: sectionIDDescription,
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseNonNullStateForUnknown(),
				},
			},
			"field_map": schema.MapNestedAttribute{
				MarkdownDescription: fieldMapDescription,
				Optional:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							MarkdownDescription: fieldIDDescription,
							Optional:            true,
							Computed:            true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseNonNullStateForUnknown(),
							},
						},
						"type": schema.StringAttribute{
							MarkdownDescription: fmt.Sprintf(enumDescription, fieldTypeDescription, fieldTypes),
							Optional:            true,
							Computed:            true,
							Default:             stringdefault.StaticString("STRING"),
							Validators: []validator.String{
								stringvalidator.OneOf(fieldTypes...),
							},
						},
						"value": schema.StringAttribute{
							MarkdownDescription: fieldValueDescription,
							Optional:            true,
							Computed:            true,
							Sensitive:           true,
							PlanModifiers: []planmodifier.String{
								PasswordValueModifierForMapField(),
							},
							Validators: []validator.String{
								stringvalidator.ConflictsWith(
									path.MatchRelative().AtParent().AtName("password_recipe"),
								),
								validateMonthYear(),
							},
						},
						"password_recipe": schema.SingleNestedAttribute{
							MarkdownDescription: passwordRecipeDescription,
							Optional:            true,
							Attributes: map[string]schema.Attribute{
								"length": schema.Int64Attribute{
									MarkdownDescription: passwordLengthDescription,
									Optional:            true,
									Computed:            true,
									Default:             int64default.StaticInt64(32),
									Validators: []validator.Int64{
										int64validator.Between(1, 64),
									},
								},
								"digits": schema.BoolAttribute{
									MarkdownDescription: passwordDigitsDescription,
									Optional:            true,
									Computed:            true,
									Default:             booldefault.StaticBool(true),
								},
								"symbols": schema.BoolAttribute{
									MarkdownDescription: passwordSymbolsDescription,
									Optional:            true,
									Computed:            true,
									Default:             booldefault.StaticBool(true),
								},
							},
						},
					},
				},
			},
		},
	}

	return &schema.Schema{
		MarkdownDescription: "A 1Password Item.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: terraformItemIDDescription,
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					validateOTP(),
				},
			},
			"uuid": schema.StringAttribute{
				MarkdownDescription: itemUUIDDescription,
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"vault": schema.StringAttribute{
				MarkdownDescription: vaultUUIDDescription,
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"category": schema.StringAttribute{
				MarkdownDescription: fmt.Sprintf(enumDescription, categoryDescription, categories),
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("login"),
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive(categories...),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"title":    schema.StringAttribute{MarkdownDescription: itemTitleDescription, Optional: true},
			"url":      schema.StringAttribute{MarkdownDescription: urlDescription, Optional: true},
			"hostname": schema.StringAttribute{MarkdownDescription: dbHostnameDescription, Optional: true},
			"database": schema.StringAttribute{MarkdownDescription: dbDatabaseDescription, Optional: true},
			"port":     schema.StringAttribute{MarkdownDescription: dbPortDescription, Optional: true},
			"type": schema.StringAttribute{
				MarkdownDescription: fmt.Sprintf(enumDescription, dbTypeDescription, dbTypes),
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive(dbTypes...),
				},
			},
			"tags": schema.ListAttribute{
				MarkdownDescription: tagsDescription,
				ElementType:         types.StringType,
				Optional:            true,
			},
			"username": schema.StringAttribute{MarkdownDescription: usernameDescription, Optional: true},
			"password": schema.StringAttribute{
				MarkdownDescription: passwordDescription,
				Optional:            true,
				Computed:            true,
				Sensitive:           true,
				PlanModifiers: []planmodifier.String{
					ValueModifier(),
				},
			},
			"password_wo": schema.StringAttribute{
				MarkdownDescription: passwordWriteOnceDescription,
				Optional:            true,
				Sensitive:           true,
				WriteOnly:           true,
			},
			"password_wo_version": schema.Int64Attribute{
				MarkdownDescription: passwordWriteOnceVersionDescription,
				Optional:            true,
			},
			"note_value": schema.StringAttribute{
				MarkdownDescription: noteValueDescription,
				Optional:            true,
				Sensitive:           true,
			},
			"note_value_wo": schema.StringAttribute{
				MarkdownDescription: noteValueWriteOnceDescription,
				Optional:            true,
				Sensitive:           true,
				WriteOnly:           true,
			},
			"note_value_wo_version": schema.Int64Attribute{
				MarkdownDescription: noteValueWriteOnceVersionDescription,
				Optional:            true,
			},
			"section_map": schema.MapNestedAttribute{
				MarkdownDescription: sectionMapDescription,
				Optional:            true,
				NestedObject:        sectionNestedObjectSchemaForMapV0,
			},
		},
		Blocks: map[string]schema.Block{
			"section": schema.ListNestedBlock{
				MarkdownDescription: sectionListDescription,
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							MarkdownDescription: sectionIDDescription,
							Optional:            true,
							Computed:            true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseNonNullStateForUnknown(),
							},
						},
						"label": schema.StringAttribute{
							MarkdownDescription: sectionLabelDescription,
							Required:            true,
						},
					},
					Blocks: map[string]schema.Block{
						"field": schema.ListNestedBlock{
							MarkdownDescription: fieldListDescription,
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"id": schema.StringAttribute{
										MarkdownDescription: fieldIDDescription,
										Optional:            true,
										Computed:            true,
										PlanModifiers: []planmodifier.String{
											stringplanmodifier.UseNonNullStateForUnknown(),
										},
									},
									"label": schema.StringAttribute{
										MarkdownDescription: fieldLabelDescription,
										Required:            true,
									},
									// Removed after v3.0.0 (section fields no longer
									// have a settable purpose) - kept here only so
									// old state still decodes.
									"purpose": schema.StringAttribute{
										MarkdownDescription: "Deprecated - section field purpose is no longer settable.",
										Optional:            true,
									},
									"type": schema.StringAttribute{
										MarkdownDescription: fmt.Sprintf(enumDescription, fieldTypeDescription, fieldTypes),
										Optional:            true,
										Computed:            true,
										Default:             stringdefault.StaticString("STRING"),
										Validators: []validator.String{
											stringvalidator.OneOf(fieldTypes...),
										},
									},
									"value": schema.StringAttribute{
										MarkdownDescription: fieldValueDescription,
										Optional:            true,
										Computed:            true,
										Sensitive:           true,
										PlanModifiers: []planmodifier.String{
											ValueModifier(),
										},
										Validators: []validator.String{
											stringvalidator.ConflictsWith(
												path.MatchRelative().AtParent().AtName("password_recipe"),
											),
											validateMonthYear(),
										},
									},
								},
								Blocks: map[string]schema.Block{
									"password_recipe": passwordRecipeBlockSchemaV0,
								},
							},
						},
					},
				},
			},
			"password_recipe": passwordRecipeBlockSchemaV0,
		},
	}
}

func upgradeItemStateV0(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
	var priorState OnePasswordItemResourceModelV0
	resp.Diagnostics.Append(req.State.Get(ctx, &priorState)...)
	if resp.Diagnostics.HasError() {
		return
	}

	upgradedState := OnePasswordItemResourceModel{
		ID:                 priorState.ID,
		UUID:               priorState.UUID,
		Vault:              priorState.Vault,
		Category:           priorState.Category,
		Title:              priorState.Title,
		URL:                priorState.URL,
		Hostname:           priorState.Hostname,
		Database:           priorState.Database,
		Port:               priorState.Port,
		Type:               priorState.Type,
		Tags:               priorState.Tags,
		Username:           priorState.Username,
		Password:           priorState.Password,
		PasswordWO:         priorState.PasswordWO,
		PasswordWOVersion:  priorState.PasswordWOVersion,
		NoteValue:          priorState.NoteValue,
		NoteValueWO:        priorState.NoteValueWO,
		NoteValueWOVersion: priorState.NoteValueWOVersion,
		SectionMap:         priorState.SectionMap,
		Recipe:             dropRecipeLetters(priorState.Recipe),
	}

	if priorState.SectionList != nil {
		upgradedState.SectionList = make([]OnePasswordItemResourceSectionListModel, len(priorState.SectionList))
		for i, s := range priorState.SectionList {
			var fields []OnePasswordItemResourceFieldModel
			if s.FieldList != nil {
				fields = make([]OnePasswordItemResourceFieldModel, len(s.FieldList))
				for j, f := range s.FieldList {
					fields[j] = OnePasswordItemResourceFieldModel{
						ID:     f.ID,
						Label:  f.Label,
						Type:   f.Type,
						Value:  f.Value,
						Recipe: dropRecipeLetters(f.Recipe),
					}
				}
			}
			upgradedState.SectionList[i] = OnePasswordItemResourceSectionListModel{
				ID:        s.ID,
				Label:     s.Label,
				FieldList: fields,
			}
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, upgradedState)...)
}

func dropRecipeLetters(prior []PasswordRecipeModelV0) []PasswordRecipeModel {
	if prior == nil {
		return nil
	}
	out := make([]PasswordRecipeModel, len(prior))
	for i, r := range prior {
		out[i] = PasswordRecipeModel{
			Length:  r.Length,
			Digits:  r.Digits,
			Symbols: r.Symbols,
		}
	}
	return out
}
