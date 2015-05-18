A Node + Express app providing a simple demonstration of authentication using json web-tokens.

Right now the code is set to expire json web-tokens after a minute and send a user a new json web-token only if that user provides a refresh token. For enhanced security the code can be modified to re-issue a new json web-token and new refresh token on every single request made to the server (this of course will have a minor performance hit since the refresh token has to be looked up each time in the database).

To run this project locally private and public rsa keys will have to be generate which are used to sign the json web-tokens and can be generated with the following commands (this is for Linux or Unix based OS's):

Private key:

openssl genrsa -out private.pem 2048

Public key:

openssl rsa -in private.pem -pubout -out public.pem
