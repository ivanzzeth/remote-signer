package types

import "time"

// RuleTemplate represents a parameterized rule template with ${variable} placeholders.
// Templates define the rule logic (config) with variables, and instances bind concrete values.
type RuleTemplate struct {
	ID             string     `json:"id" gorm:"primaryKey;type:varchar(128)"`
	Name           string     `json:"name" gorm:"type:varchar(255)"`
	Description    string     `json:"description,omitempty" gorm:"type:text"`
	Type           RuleType   `json:"type" gorm:"type:varchar(64)"`
	Mode           RuleMode   `json:"mode" gorm:"type:varchar(16)"`
	Variables      []byte     `json:"variables" gorm:"type:jsonb"`        // []TemplateVariable
	Config         []byte     `json:"config" gorm:"type:jsonb"`           // Template config with ${var} (contains rules array)
	BudgetMetering []byte     `json:"budget_metering,omitempty" gorm:"type:jsonb"` // *BudgetMetering (nullable)
	TestVariables  []byte     `json:"test_variables,omitempty" gorm:"type:jsonb"`  // map[string]string for template validation
	Source         RuleSource `json:"source" gorm:"type:varchar(32)"`
	Enabled        bool       `json:"enabled" gorm:"index"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// TableName specifies the table name for GORM
func (RuleTemplate) TableName() string {
	return "rule_templates"
}

// TemplateVariable defines a variable in a rule template
type TemplateVariable struct {
	Name        string `json:"name" yaml:"name"`
	Type        string `json:"type" yaml:"type"`                           // "address", "uint256", "string", "address_list", "uint256_list"
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Required    bool   `json:"required" yaml:"required"`                   // default true
	Default     string `json:"default,omitempty" yaml:"default,omitempty"` // default value if not required
}

// BudgetMetering defines how to extract spending amounts from transactions.
// Templates define the metering method; instances provide budget limits.
type BudgetMetering struct {
	Method     string `json:"method" yaml:"method"`                          // "none", "count_only", "calldata_param", "typed_data_field", "tx_value"
	Unit       string `json:"unit" yaml:"unit"`                              // custom unit: "usdt", "auth", "eth"
	ParamIndex int    `json:"param_index,omitempty" yaml:"param_index,omitempty"` // for calldata_param
	ParamType  string `json:"param_type,omitempty" yaml:"param_type,omitempty"`   // for calldata_param: "uint256", etc.
	FieldPath  string `json:"field_path,omitempty" yaml:"field_path,omitempty"`   // for typed_data_field: "message.amount"
	Decimals   int    `json:"decimals,omitempty" yaml:"decimals,omitempty"`
}
