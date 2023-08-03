# web3-auth-py

This repo is deprecated. Use https://github.com/spruceid/siwe-py

A web3-based authentication library for python.

This library can be used with any framework of your choice to provide a centralized authentication for blockchain users (using metamask or other web3 provider).

Using this authentication method, User's id is a blockchain public key.

## Install

```
pip install web3auth
```

## Usage

First, you need to setup a DomainData (describing your service/application) and AuthManager (an object, that will handle auth):

```python
    import web3auth as w3a

    ...

    DOMAIN_DATA = w3a.DomainData(PROJECT_NAME, VERSION, CHAIN_ID, ADDRESS)
    AUTH_MANAGER = w3a.AuthManager.from_domain_data(DOMAIN_DATA)
```

Then, it is possible to use `AUTH_MANAGER` to create a EIP712 structure, that a user with address `user_address` has to sign to authenticate:

```python
    sign_data = AUTH_MANAGER.generate_sign_data(user_address, type="dict")
```

After a signature is made on a client side (TODO: add example of signing a data using JavaScript) a user has to send a `signature`, `noonce` and a `salt` back to backend side (`noonce` and `salt` can be found in `sign_data`), that can be processed to generate a JWT:

```python
    try:
        token_manager = AUTH_MANAGER.authenticate(user_address, noonce, salt, signature)
    except w3a.AuthError as error:
        ... # process error

    access_token = token_manager.create_access_token(ACCESS_TOKEN_EXPIRES_AT, SECRET_KEY)
```

The token should be sent back to user. On a backend side that token can be verified using:

```python
    try:
        return w3a.validate_token(access_token, SECRET_KEY)
    except w3a.AuthError as error:
        ... # process error
```

## Version info

Current version is 1.4.0 and is the only stable version that is recommended to be used.

## Future plans

-   Right now, the `noonce` is stored in `w3a.AuthManager` and should have an option to override this mechanism to store that data on database.

-   Rework how salt is used. Right now it is randomly generated each time, sign data is generated. This should be changed to generate salt only once (or to be provided).

-   Rework DomainData - make address and version optional.
