package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "user",
				Usage: "What permissions does this user have?",
				Action: func(c *cli.Context) error {
					cfg, _ := config.LoadDefaultConfig(context.TODO())
					client := iam.NewFromConfig(cfg)

					if c.Args().Len() != 1 {
						println("Please provide username")
						return nil
					}
					username := c.Args().Get(0)
					userInlinePolicies(username, *client)
					userManagedPolicies(username, *client)
					groups := groupsForUser(username, *client)
					for _, group := range groups.Groups {
						groupInlinePolicies(*group.GroupName, *client)
						groupManagedPolicies(*group.GroupName, *client)
					}

					return nil
				},
			},
		}}
	app.RunAndExitOnError()
}

func userInlinePolicies(username string, client iam.Client) {
	inlinePolicies, err := client.ListUserPolicies(context.TODO(), &iam.ListUserPoliciesInput{
		UserName: &username,
	})
	if err != nil {
		panic(err)
	}

	if len(inlinePolicies.PolicyNames) != 0 {
		fmt.Printf("Inline policies for user: %v\n", username)
		fmt.Println("=====================================")
		for _, policyName := range inlinePolicies.PolicyNames {
			fmt.Println("Policy name: " + policyName)
			fmt.Println("-------------------------------------")
			policy, err := client.GetUserPolicy(context.TODO(), &iam.GetUserPolicyInput{
				UserName:   &username,
				PolicyName: &policyName,
			})
			if err != nil {
				panic(err)
			}
			// decode and print policy document
			decodedDocument, err := url.QueryUnescape(*policy.PolicyDocument)
			if err != nil {
				fmt.Errorf("Error: failed to decode policy document")
				panic(err)
			}

			fmt.Printf("%v\n", decodedDocument)
		}
	}
}

func userManagedPolicies(username string, client iam.Client) {
	maxItems := int32(1000)
	policies, err := client.ListAttachedUserPolicies(context.TODO(), &iam.ListAttachedUserPoliciesInput{
		MaxItems: &maxItems,
		UserName: &username,
	})

	if err != nil {
		panic(err)
	}

	if policies.IsTruncated {
		println("Warning: more than 1000 policies found. Some permissions may not be found.")
	}

	if len(policies.AttachedPolicies) != 0 {
		fmt.Printf("Attached policies for user: %v\n", username)
		fmt.Println("=====================================")
		for _, policy := range policies.AttachedPolicies {
			fmt.Println("Policy name: " + *policy.PolicyName)
			fmt.Println("-------------------------------------")

			policyOutput, err := client.GetPolicy(context.TODO(), &iam.GetPolicyInput{
				PolicyArn: policy.PolicyArn,
			})
			if err != nil {
				panic(err)
			}

			fmt.Printf("(%v)\n", *policyOutput.Policy.Description)
			// get policy version
			policyVersion, err := client.GetPolicyVersion(context.TODO(), &iam.GetPolicyVersionInput{
				PolicyArn: policy.PolicyArn,
				VersionId: policyOutput.Policy.DefaultVersionId,
			})
			if err != nil {
				panic(err)
			}

			// decode and print policy document
			decodedDocument, err := url.QueryUnescape(*policyVersion.PolicyVersion.Document)
			if err != nil {
				fmt.Errorf("Error: failed to decode policy document")
				panic(err)
			}
			println(decodedDocument)
		}
	}
}

// func getPolicyDetails(policyArn string, client iam.Client) {
// 	policy, err := client.GetPolicy(context.TODO(), &iam.GetPolicyInput{
// 		PolicyArn: &policyArn,
// 	})
// 	if err != nil {
// 		panic(err)
// 	}
// 	println(*policy.Policy.PolicyName)
// }

func groupsForUser(username string, client iam.Client) (groups *iam.ListGroupsForUserOutput) {
	groups, err := client.ListGroupsForUser(context.TODO(), &iam.ListGroupsForUserInput{
		UserName: &username,
	})
	if err != nil {
		panic(err)
	}
	return groups
}

func groupInlinePolicies(groupName string, client iam.Client) {
	inlinePolicies, err := client.ListGroupPolicies(context.TODO(), &iam.ListGroupPoliciesInput{
		GroupName: &groupName,
	})
	if err != nil {
		panic(err)
	}

	if len(inlinePolicies.PolicyNames) != 0 {
		fmt.Printf("Inline policies for group: %v\n", groupName)
		fmt.Println("=====================================")
		for _, policyName := range inlinePolicies.PolicyNames {
			fmt.Printf("Policy name: %v\n", policyName)
			fmt.Println("-------------------------------------")
			policy, err := client.GetGroupPolicy(context.TODO(), &iam.GetGroupPolicyInput{
				GroupName:  &groupName,
				PolicyName: &policyName,
			})
			if err != nil {
				panic(err)
			}
			// decode and print policy document
			decodedDocument, err := url.QueryUnescape(*policy.PolicyDocument)
			if err != nil {
				fmt.Errorf("Error: failed to decode policy document")
				panic(err)
			}

			fmt.Printf("%v\n", decodedDocument)
		}
	}
}

func groupManagedPolicies(groupname string, client iam.Client) {
	maxItems := int32(1000)
	policies, err := client.ListAttachedGroupPolicies(context.TODO(), &iam.ListAttachedGroupPoliciesInput{
		MaxItems:  &maxItems,
		GroupName: &groupname,
	})

	if err != nil {
		panic(err)
	}

	if policies.IsTruncated {
		println("Warning: more than 1000 policies found. Some permissions may not be found.")
	}

	if len(policies.AttachedPolicies) != 0 {
		fmt.Printf("Attached policies for group: %v\n", groupname)
		fmt.Println("=====================================")
		for _, policy := range policies.AttachedPolicies {
			fmt.Println("Policy name: " + *policy.PolicyName)
			fmt.Println("-------------------------------------")

			policyOutput, err := client.GetPolicy(context.TODO(), &iam.GetPolicyInput{
				PolicyArn: policy.PolicyArn,
			})
			if err != nil {
				panic(err)
			}

			fmt.Printf("(%v)\n", *policyOutput.Policy.Description)
			// get policy version
			policyVersion, err := client.GetPolicyVersion(context.TODO(), &iam.GetPolicyVersionInput{
				PolicyArn: policy.PolicyArn,
				VersionId: policyOutput.Policy.DefaultVersionId,
			})
			if err != nil {
				panic(err)
			}

			// decode and print policy document
			decodedDocument, err := url.QueryUnescape(*policyVersion.PolicyVersion.Document)
			if err != nil {
				fmt.Errorf("Error: failed to decode policy document")
				panic(err)
			}
			println(decodedDocument)
		}
	}
}
