// Package policy evaluates the wellhead.dev/ annotation rules with the CEL the admission policies run.
package policy

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	"go.yaml.in/yaml/v3"

	"github.com/wellhead-dev/wellhead/deploy"
)

type ruleFile struct {
	SpecVersion string       `yaml:"specVersion"`
	Variables   []variable   `yaml:"variables"`
	Validations []validation `yaml:"validations"`
}

type variable struct {
	Name       string `yaml:"name"`
	Expression string `yaml:"expression"`
}

type validation struct {
	ID                string `yaml:"id"`
	Expression        string `yaml:"expression"`
	MessageExpression string `yaml:"messageExpression"`
}

type compiledVariable struct {
	name    string
	program cel.Program
}

type compiledRule struct {
	id      string
	check   cel.Program
	message cel.Program
}

// Violation is one rule an ExternalSecret breaks.
type Violation struct {
	Rule    string
	Message string
}

// Policy is the compiled rule set.
type Policy struct {
	SpecVersion string
	variables   []compiledVariable
	rules       []compiledRule
}

// Load compiles the rules embedded from the Helm chart.
func Load() (*Policy, error) {
	return Parse(deploy.Rules)
}

// Parse compiles a rule file.
func Parse(data []byte) (*Policy, error) {
	var rf ruleFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	env, err := cel.NewEnv(
		cel.Variable("object", cel.DynType),
		cel.Variable("variables", cel.MapType(cel.StringType, cel.DynType)),
		cel.OptionalTypes(),
		ext.Strings(ext.StringsVersion(2)),
	)
	if err != nil {
		return nil, err
	}
	p := &Policy{SpecVersion: rf.SpecVersion}
	for _, v := range rf.Variables {
		prg, err := compile(env, v.Expression)
		if err != nil {
			return nil, fmt.Errorf("variable %s: %w", v.Name, err)
		}
		p.variables = append(p.variables, compiledVariable{name: v.Name, program: prg})
	}
	seen := map[string]bool{}
	for _, v := range rf.Validations {
		if v.ID == "" || seen[v.ID] {
			return nil, fmt.Errorf("validation %q: missing or duplicate id", v.ID)
		}
		seen[v.ID] = true
		check, err := compile(env, v.Expression)
		if err != nil {
			return nil, fmt.Errorf("%s expression: %w", v.ID, err)
		}
		msg, err := compile(env, v.MessageExpression)
		if err != nil {
			return nil, fmt.Errorf("%s messageExpression: %w", v.ID, err)
		}
		p.rules = append(p.rules, compiledRule{id: v.ID, check: check, message: msg})
	}
	return p, nil
}

func compile(env *cel.Env, expr string) (cel.Program, error) {
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, iss.Err()
	}
	return env.Program(ast)
}

// RuleIDs lists every rule in file order.
func (p *Policy) RuleIDs() []string {
	ids := make([]string, 0, len(p.rules))
	for _, r := range p.rules {
		ids = append(ids, r.id)
	}
	return ids
}

// Evaluate runs every rule against one ExternalSecret. An evaluation error is reported as a violation of
// that rule, because the CLI is the strict side: admission ignores errors only while it warns.
func (p *Policy) Evaluate(object map[string]any) []Violation {
	vars := map[string]any{}
	act := map[string]any{"object": object, "variables": vars}
	var out []Violation
	for _, v := range p.variables {
		val, _, err := v.program.Eval(act)
		if err != nil {
			return []Violation{{Rule: "WH000", Message: fmt.Sprintf("WH000: variable %s cannot be evaluated: %v", v.name, err)}}
		}
		vars[v.name] = val
	}
	for _, r := range p.rules {
		val, _, err := r.check.Eval(act)
		if err != nil {
			out = append(out, Violation{Rule: r.id, Message: fmt.Sprintf("%s: cannot be evaluated: %v", r.id, err)})
			continue
		}
		if ok, isBool := val.Value().(bool); isBool && ok {
			continue
		}
		out = append(out, Violation{Rule: r.id, Message: message(r, act)})
	}
	return out
}

func message(r compiledRule, act map[string]any) string {
	val, _, err := r.message.Eval(act)
	if err != nil {
		return r.id + ": rule failed"
	}
	return text(val)
}

func text(v ref.Val) string {
	s, ok := v.Value().(string)
	if !ok {
		return fmt.Sprint(v.Value())
	}
	return strings.Join(strings.Fields(s), " ")
}
