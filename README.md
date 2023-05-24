# iamw

A CLI tool to print all access that a user has.

To identify all permissions that a user has following steps need to be performed:

1. Get all in-line policies that are attached to the user
2. Get all attached policies that are attached to the user
3. Get all groups that a user is a member of
4. Get all in-line policies that are attached to the groups
5. Get all attached policies that are attached to the groups

There is no easy way to do this using the AWS CLI tool. `iamw` performs all these steps and prints all the permissions that a user has.

## Usage

```sh
iamw user user1
iamw role role1 // to be implemented
```
