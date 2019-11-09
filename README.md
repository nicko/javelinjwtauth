# Example JWT Auth Server

Note: this is not production worthy and was built as an example for a blog post.

    
[![Known Vulnerabilities](https://snyk.io/test/github/nicko/javelinjwtauth/badge.svg?targetFile=pom.xml)](https://snyk.io/test/github/nicko/javelinjwtauth?targetFile=pom.xml)

## Data Model

Application
* Has a name
* Has an API key to identify it
* Has many Users
* Has many Roles
* Has many Sessions

Role
* Has many Permissions
* Can assign to Users

User
* Has many Roles

Session
* Has a Json Web Token

JWT
* Has a Subject (the user's UUID)
* Has a Scope (Permissions list joined and separated by a space)

## Components

### Server

1. Must allow creation of new Application
2. Must allow registration of users
3. Must allow creation of roles & permissions to use as 'claims'
4. Must allow users to log in and create a JWT
5. Must allow clients to download its public key

### Client

1. Must get public key of Application it identifies as
2. Must attempt to log in user
3. Must validate JWT when it is returned
4. Must extract permissions from JWT 'claims'
