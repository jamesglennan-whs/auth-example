# Example JWT Auth service

This is used to test out prospective API gateways by 'dummying' a login process for token Authentication.

Requests are sent to port `3000`

Please send a request using 'curl -L -c cookies -v localhost:3000 -H 'User: user1' -H 'Pass: password1'

Or using the user name `user2/password2`
User 1's token will contain tenantA and User 2's will be tenantB
You can also specify the token with the header `Authorization: bearer <TOKEN HERE>`
Tokens will expire after 5 mins, they will not auto-renew-> login with user and password to get a new token