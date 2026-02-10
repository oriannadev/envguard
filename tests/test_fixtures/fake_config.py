# Fake Python config -- ALL CREDENTIALS ARE INTENTIONALLY FAKE
# Used for testing envguard's detection capabilities.

API_KEY = "sk-fakePythonTestKey1234567890abcdefghijk"

config = {
    "github_token": "ghp_fakeGitHubTokenForTesting12345678901234",
    "secret_key": "my-super-secret-application-key-do-not-share",
    "password": "hunter2-not-a-real-password-obviously",
}

DATABASE_URL = "mysql://root:rootpassword@localhost:3306/testdb"

# This mimics a private key block
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIFAKEprivateKEYcontentTHATisNOTreal1234567890ABCDEFGHIJ
KLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789FAKE
-----END RSA PRIVATE KEY-----"""

STRIPE_KEY = "sk_test_fakeStripeTestingKey1234567890abcdefgh"

SLACK_TOKEN = "xoxp-fake-slack-user-token-for-testing-123"
