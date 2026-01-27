package main

import (
	"fmt"
	"log"

	"github.com/pilacorp/go-auth-sdk/auth/policy"
)

func main() {
	fmt.Println("=== Creating and Validating Policies ===\n")

	// Example 1: Create a simple policy with default specification
	fmt.Println("Example 1: Simple Policy")
	fmt.Println("-------------------------")
	simplePolicy := policy.NewPolicy(
		policy.WithStatements(
			policy.NewStatement(
				policy.EffectAllow,
				[]policy.Action{policy.NewAction("Issuer:Create")},
				[]policy.Resource{policy.NewResource(policy.ResourceObjectIssuer)},
				policy.NewCondition(),
			),
		),
	)

	if simplePolicy.IsValid() {
		fmt.Println("✓ Simple policy is valid")
		fmt.Printf("  Number of statements: %d\n", len(simplePolicy.Permissions))
	} else {
		log.Fatal("✗ Simple policy is invalid")
	}

	// Example 2: Create a policy with multiple statements
	fmt.Println("\nExample 2: Policy with Multiple Statements")
	fmt.Println("-------------------------------------------")
	multiStatementPolicy := policy.NewPolicy(
		policy.WithStatements(
			// Allow statement
			policy.NewStatement(
				policy.EffectAllow,
				[]policy.Action{
					policy.NewAction("Credential:Create"),
					policy.NewAction("Credential:Update"),
				},
				[]policy.Resource{
					policy.NewResource(policy.ResourceObjectCredential),
					policy.NewResource(policy.ResourceObjectIssuer),
				},
				policy.NewCondition(),
			),
			// Deny statement
			policy.NewStatement(
				policy.EffectDeny,
				[]policy.Action{policy.NewAction("Credential:Delete")},
				[]policy.Resource{policy.NewResource(policy.ResourceObjectCredential)},
				policy.NewCondition(),
			),
		),
	)

	if multiStatementPolicy.IsValid() {
		fmt.Println("✓ Multi-statement policy is valid")
		fmt.Printf("  Number of statements: %d\n", len(multiStatementPolicy.Permissions))
		for i, stmt := range multiStatementPolicy.Permissions {
			fmt.Printf("  Statement %d: %s\n", i+1, stmt.Effect)
		}
	} else {
		log.Fatal("✗ Multi-statement policy is invalid")
	}

	// Example 3: Create a policy with conditions
	fmt.Println("\nExample 3: Policy with Conditions")
	fmt.Println("----------------------------------")
	conditions := policy.NewCondition()
	conditions.Add("StringEquals", "tenant", "example-tenant")
	conditions.Add("StringNotEquals", "environment", "production")

	conditionalPolicy := policy.NewPolicy(
		policy.WithStatements(
			policy.NewStatement(
				policy.EffectAllow,
				[]policy.Action{policy.NewAction("Issuer:Create")},
				[]policy.Resource{policy.NewResource(policy.ResourceObjectIssuer)},
				conditions,
			),
		),
	)

	if conditionalPolicy.IsValid() {
		fmt.Println("✓ Conditional policy is valid")
		fmt.Printf("  Conditions: %v\n", conditionalPolicy.Permissions[0].Conditions)
	} else {
		log.Fatal("✗ Conditional policy is invalid")
	}

	// Example 4: Create a policy with custom specification
	fmt.Println("\nExample 4: Policy with Custom Specification")
	fmt.Println("-------------------------------------------")
	customSpec := policy.NewSpecification(
		[]policy.ActionObject{policy.ActionObjectIssuer, policy.ActionObjectCredential},
		[]policy.ActionVerb{policy.ActionVerbCreate, policy.ActionVerbUpdate},
		[]policy.ResourceObject{policy.ResourceObjectIssuer, policy.ResourceObjectCredential},
	)

	customSpecPolicy := policy.NewPolicy(
		policy.WithSpecification(customSpec),
		policy.WithStatements(
			policy.NewStatement(
				policy.EffectAllow,
				[]policy.Action{policy.NewAction("Issuer:Create")},
				[]policy.Resource{policy.NewResource(policy.ResourceObjectIssuer)},
				policy.NewCondition(),
			),
		),
	)

	if customSpecPolicy.IsValid() {
		fmt.Println("✓ Custom specification policy is valid")
		fmt.Printf("  Specification action objects: %d\n", len(customSpecPolicy.Specification.ActionObjects))
		fmt.Printf("  Specification action verbs: %d\n", len(customSpecPolicy.Specification.ActionVerbs))
		fmt.Printf("  Specification resource objects: %d\n", len(customSpecPolicy.Specification.ResourceObjects))
	} else {
		log.Fatal("✗ Custom specification policy is invalid")
	}

	fmt.Println("\n=== All Examples Completed Successfully ===")
}
