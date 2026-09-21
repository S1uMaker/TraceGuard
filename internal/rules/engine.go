// Package rules evaluates explicit, local rules against successful exec events.
package rules

import (
	"fmt"
	"path"

	"github.com/zjc20/traceguard/internal/config"
	"github.com/zjc20/traceguard/internal/model"
)

type Engine struct {
	rules []config.Rule
}

// Result separates alerts from rules whose matching Docker event was excluded.
// Both slices follow configuration order.
type Result struct {
	Alerts        []model.Alert
	ExcludedRules []string
}

func New(rules []config.Rule) (*Engine, error) {
	if err := config.ValidateRules(rules); err != nil {
		return nil, err
	}
	engine := &Engine{rules: make([]config.Rule, 0, len(rules))}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		// Own the slices and UID value so callers cannot alter an active engine.
		rule.Executables = append([]string(nil), rule.Executables...)
		rule.ContainerNames = append([]string(nil), rule.ContainerNames...)
		rule.ExcludeContainerNames = append([]string(nil), rule.ExcludeContainerNames...)
		if rule.UID != nil {
			uid := *rule.UID
			rule.UID = &uid
		}
		engine.rules = append(engine.rules, rule)
	}
	return engine, nil
}

// Match returns one alert per matching, non-excluded rule, in configuration order.
func (engine *Engine) Match(event model.Event) []model.Alert {
	return engine.Evaluate(event).Alerts
}

// Evaluate matches all positive conditions before applying container exclusions.
// Rule fields are combined with AND; alternatives inside each list use OR. An
// unknown source never satisfies docker or host scope. Exclusions match exact
// Docker container names and suppress only their own rule's alert.
func (engine *Engine) Evaluate(event model.Event) Result {
	var result Result
	if event.Type != "process_exec" || event.Filename == "" {
		return result
	}
	for _, rule := range engine.rules {
		if rule.Scope != "any" && rule.Scope != event.Source.Kind {
			continue
		}
		matchedExecutable := ""
		for _, executable := range rule.Executables {
			if (path.IsAbs(executable) && executable == event.Filename) ||
				(!path.IsAbs(executable) && executable == path.Base(event.Filename)) {
				matchedExecutable = executable
				break
			}
		}
		if matchedExecutable == "" {
			continue
		}
		if len(rule.ContainerNames) > 0 {
			if event.Source.Kind != "docker" || !contains(rule.ContainerNames, event.Source.ContainerName) {
				continue
			}
		}
		if rule.UID != nil && event.UID != *rule.UID {
			continue
		}
		if event.Source.Kind == "docker" && contains(rule.ExcludeContainerNames, event.Source.ContainerName) {
			result.ExcludedRules = append(result.ExcludedRules, rule.ID)
			continue
		}
		evidence := []string{
			"event_type=process_exec (successful exec)",
			fmt.Sprintf("source.kind=%q; rule.scope=%q", event.Source.Kind, rule.Scope),
			fmt.Sprintf("filename=%q matched executable=%q", event.Filename, matchedExecutable),
		}
		if len(rule.ContainerNames) > 0 {
			evidence = append(evidence, fmt.Sprintf("container_name=%q matched configured name", event.Source.ContainerName))
		}
		if rule.UID != nil {
			evidence = append(evidence, fmt.Sprintf("uid=%d matched configured uid", event.UID))
		}
		result.Alerts = append(result.Alerts, model.Alert{
			ID: event.ID + ":" + rule.ID, EventID: event.ID,
			ObservedAt: event.ObservedAt, RuleID: rule.ID, RuleName: rule.Name,
			Severity: rule.Severity, Description: rule.Description,
			Evidence: evidence, Event: event,
		})
	}
	return result
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
