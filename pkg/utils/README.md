# Description
Provides some functions that the base dns package does not offer, such as:
1. Getting the value of a RR
2. Getting the type, name, and DO flag of a DNS message
3. Converting a string to a lower case FQDN
4. Getting the parent FQDN of a given domain

# To Do
1. It might be more efficient to create wrappers. At the moment, we need to convert the domain name every time we call `getName()`. Also, a wrapper would allow us to use `object.getName()`.
2. Consider the possibility of multiple questions (?)