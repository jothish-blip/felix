package discovery

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/html"
)

// FormField describes an individual input, select, or textarea control within a form.
type FormField struct {
	Name         string `json:"name"`
	Type         string `json:"type"` // text, password, email, hidden, file, checkbox, radio, select, textarea
	DefaultValue string `json:"default_value,omitempty"`
	Required     bool   `json:"required"`
	IsAuthField  bool   `json:"is_auth_field"`
}

// DiscoveredForm represents a structured HTML form extracted from an application page.
type DiscoveredForm struct {
	Action      string      `json:"action"`
	Method      string      `json:"method"`
	Enctype     string      `json:"enctype"`
	Purpose     string      `json:"purpose"` // LOGIN, REGISTRATION, PASSWORD_RESET, FILE_UPLOAD, SEARCH, GENERIC
	Fields      []FormField `json:"fields"`
	HasPassword bool        `json:"has_password"`
	HasFileUpload bool      `json:"has_file_upload"`
	SourcePage  string      `json:"source_page"`
}

// FormExtractor parses HTML documents to discover forms without executing or submitting them.
type FormExtractor struct{}

// NewFormExtractor creates a new FormExtractor instance.
func NewFormExtractor() *FormExtractor {
	return &FormExtractor{}
}

// ExtractForms parses raw HTML content and resolves form targets relative to the base URL.
func (fe *FormExtractor) ExtractForms(htmlContent string, baseURL *url.URL) []DiscoveredForm {
	var forms []DiscoveredForm
	tokenizer := html.NewTokenizer(strings.NewReader(htmlContent))

	var currentForm *DiscoveredForm
	inForm := false

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			if tokenizer.Err() == io.EOF {
				if inForm && currentForm != nil {
					forms = append(forms, *currentForm)
				}
				return forms
			}
			return forms

		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			tagName := strings.ToLower(token.Data)

			if tagName == "form" {
				if inForm && currentForm != nil {
					forms = append(forms, *currentForm)
				}
				inForm = true
				currentForm = &DiscoveredForm{
					Method:     "GET",
					Enctype:    "application/x-www-form-urlencoded",
					SourcePage: baseURL.String(),
					Purpose:    "GENERIC",
				}

				for _, attr := range token.Attr {
					key := strings.ToLower(attr.Key)
					val := strings.TrimSpace(attr.Val)
					switch key {
					case "action":
						if val == "" {
							currentForm.Action = baseURL.String()
						} else if relURL, err := baseURL.Parse(val); err == nil {
							currentForm.Action = relURL.String()
						} else {
							currentForm.Action = val
						}
					case "method":
						if val != "" {
							currentForm.Method = strings.ToUpper(val)
						}
					case "enctype":
						if val != "" {
							currentForm.Enctype = strings.ToLower(val)
						}
					}
				}
				if currentForm.Action == "" {
					currentForm.Action = baseURL.String()
				}
				continue
			}

			if inForm && currentForm != nil {
				switch tagName {
				case "input":
					field := FormField{
						Type: "text",
					}
					for _, attr := range token.Attr {
						k := strings.ToLower(attr.Key)
						v := strings.TrimSpace(attr.Val)
						switch k {
						case "name":
							field.Name = v
						case "type":
							if v != "" {
								field.Type = strings.ToLower(v)
							}
						case "value":
							// Only preserve non-sensitive default values
							if field.Type == "hidden" && len(v) < 128 {
								field.DefaultValue = v
							}
						case "required":
							field.Required = true
						}
					}
					if field.Name != "" {
						if field.Type == "password" {
							currentForm.HasPassword = true
							field.IsAuthField = true
						}
						if field.Type == "file" {
							currentForm.HasFileUpload = true
						}
						currentForm.Fields = append(currentForm.Fields, field)
					}

				case "textarea":
					field := FormField{Type: "textarea"}
					for _, attr := range token.Attr {
						k := strings.ToLower(attr.Key)
						v := strings.TrimSpace(attr.Val)
						if k == "name" {
							field.Name = v
						} else if k == "required" {
							field.Required = true
						}
					}
					if field.Name != "" {
						currentForm.Fields = append(currentForm.Fields, field)
					}

				case "select":
					field := FormField{Type: "select"}
					for _, attr := range token.Attr {
						k := strings.ToLower(attr.Key)
						v := strings.TrimSpace(attr.Val)
						if k == "name" {
							field.Name = v
						} else if k == "required" {
							field.Required = true
						}
					}
					if field.Name != "" {
						currentForm.Fields = append(currentForm.Fields, field)
					}
				}
			}

		case html.EndTagToken:
			token := tokenizer.Token()
			if strings.ToLower(token.Data) == "form" && inForm && currentForm != nil {
				// Classify Form Purpose
				classifyFormPurpose(currentForm)
				forms = append(forms, *currentForm)
				currentForm = nil
				inForm = false
			}
		}
	}
}

func classifyFormPurpose(form *DiscoveredForm) {
	if form.HasFileUpload || strings.Contains(form.Enctype, "multipart/form-data") {
		form.Purpose = "FILE_UPLOAD"
	}

	lowerAction := strings.ToLower(form.Action)
	var fieldNames []string
	for _, f := range form.Fields {
		fieldNames = append(fieldNames, strings.ToLower(f.Name))
	}
	allFieldText := strings.Join(fieldNames, " ")

	if form.HasPassword {
		if strings.Contains(lowerAction, "register") || strings.Contains(lowerAction, "signup") ||
			strings.Contains(lowerAction, "sign-up") || strings.Contains(allFieldText, "confirm") ||
			strings.Contains(allFieldText, "repassword") || strings.Contains(allFieldText, "terms") {
			form.Purpose = "REGISTRATION"
		} else {
			form.Purpose = "LOGIN"
		}
	} else if strings.Contains(lowerAction, "reset") || strings.Contains(lowerAction, "forgot") ||
		strings.Contains(lowerAction, "recovery") {
		form.Purpose = "PASSWORD_RESET"
	} else if form.Method == "GET" && (strings.Contains(allFieldText, "q") || strings.Contains(allFieldText, "search") || strings.Contains(allFieldText, "query")) {
		form.Purpose = "SEARCH"
	}
}

// IngestForms converts discovered HTML forms into inventory assets, relations, and input parameters.
func (fe *FormExtractor) IngestForms(
	inv *Inventory,
	asmID, execID, targetID string,
	appAssetID string,
	forms []DiscoveredForm,
) []string {
	var formIDs []string

	for idx, f := range forms {
		cleanAction := strings.TrimSpace(f.Action)
		canonicalID := fmt.Sprintf("%s %s#%d", f.Method, cleanAction, idx)

		formAsset := Asset{
			ID:              uuid.New().String(),
			AssessmentID:    asmID,
			ExecutionID:     execID,
			TargetID:        targetID,
			Type:            AssetTypeForm,
			CanonicalID:     canonicalID,
			ParentID:        appAssetID,
			DisplayName:     fmt.Sprintf("Form [%s] %s (%s)", f.Method, cleanAction, f.Purpose),
			SourceAsset:     f.SourcePage,
			DiscoveryMethod: "HTML_PARSING",
			DiscoveryStatus: StatusObserved,
			Confidence:      ConfidenceHigh,
			InScope:         true,
			Metadata: map[string]any{
				"action":          cleanAction,
				"method":          f.Method,
				"enctype":         f.Enctype,
				"purpose":         f.Purpose,
				"field_count":     len(f.Fields),
				"has_password":    f.HasPassword,
				"has_file_upload": f.HasFileUpload,
			},
			Evidence: map[string]any{
				"source_page": f.SourcePage,
				"purpose":     f.Purpose,
			},
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		}
		fID := inv.AddAsset(formAsset)
		formIDs = append(formIDs, fID)

		// Link Application CONTAINS_FORM Form
		if appAssetID != "" {
			inv.AddRelation(Relation{
				ID:            uuid.New().String(),
				AssessmentID:  asmID,
				ExecutionID:   execID,
				SourceAssetID: appAssetID,
				TargetAssetID: fID,
				RelationType:  RelContainsForm,
				Evidence:      fmt.Sprintf("HTML form %s found on page %s", canonicalID, f.SourcePage),
				Confidence:    ConfidenceHigh,
			})
		}

		// Register each field as an input parameter
		for _, field := range f.Fields {
			paramCanonical := fmt.Sprintf("%s:form:%s", cleanAction, field.Name)
			paramAsset := Asset{
				ID:              uuid.New().String(),
				AssessmentID:    asmID,
				ExecutionID:     execID,
				TargetID:        targetID,
				Type:            AssetTypeParameter,
				CanonicalID:     paramCanonical,
				ParentID:        fID,
				DisplayName:     fmt.Sprintf("Field %s (%s)", field.Name, field.Type),
				SourceAsset:     f.SourcePage,
				DiscoveryMethod: "HTML_PARSING",
				DiscoveryStatus: StatusObserved,
				Confidence:      ConfidenceHigh,
				InScope:         true,
				Metadata: map[string]any{
					"name":          field.Name,
					"location":      string(ParamLocForm),
					"input_type":    field.Type,
					"required":      field.Required,
					"is_auth_field": field.IsAuthField,
					"action":        cleanAction,
				},
				Evidence: map[string]any{
					"form_action": cleanAction,
					"source_page": f.SourcePage,
				},
				FirstSeen: time.Now().UTC(),
				LastSeen:  time.Now().UTC(),
			}
			paramID := inv.AddAsset(paramAsset)

			// Link Form HAS_INPUT Parameter
			inv.AddRelation(Relation{
				ID:            uuid.New().String(),
				AssessmentID:  asmID,
				ExecutionID:   execID,
				SourceAssetID: fID,
				TargetAssetID: paramID,
				RelationType:  RelHasInput,
				Evidence:      fmt.Sprintf("Form input %s (%s)", field.Name, field.Type),
				Confidence:    ConfidenceHigh,
			})
		}
	}

	return formIDs
}
