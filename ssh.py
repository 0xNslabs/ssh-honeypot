import os
import argparse
from warnings import filterwarnings
filterwarnings("ignore")
from twisted.internet import reactor, endpoints
from twisted.conch.ssh import factory, keys, userauth, connection, transport
from twisted.cred import portal, credentials, error
from twisted.logger import textFileLogObserver
from twisted.python import log
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from zope.interface import implementer
from twisted.internet import defer
script_dir = os.path.dirname(os.path.abspath(__file__))

@implementer(portal.IRealm)
class SimpleSSHRealm:
    def requestAvatar(self, avatar_id, mind, *interfaces):
        if conchinterfaces.IConchUser in interfaces:
            return interfaces[0], SimpleSSHAvatar(avatar_id), lambda: None
        else:
            raise Exception("No supported interfaces found.")

def getRSAKeys():
    public_key_path = os.path.join(script_dir, 'id_rsa.pub')
    private_key_path = os.path.join(script_dir, 'id_rsa')

    if not (os.path.exists(public_key_path) and os.path.exists(private_key_path)):
        ssh_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend())

        public_key = ssh_key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH)

        private_key = ssh_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption())

        with open(public_key_path, 'wb') as key_file:
            key_file.write(public_key)

        with open(private_key_path, 'wb') as key_file:
            key_file.write(private_key)
    else:
        with open(public_key_path, 'rb') as key_file:
            public_key = key_file.read()

        with open(private_key_path, 'rb') as key_file:
            private_key = key_file.read()

    return public_key, private_key

class CustomSSHServerTransport(transport.SSHServerTransport):
    def __init__(self, our_version_string):
        self.ourVersionString = our_version_string.encode()
        transport.SSHServerTransport.__init__(self)

class SimpleSSHFactory(factory.SSHFactory):
    def __init__(self, our_version_string):
        self.ourVersionString = our_version_string

    publicKeys = {
        b'ssh-rsa': keys.Key.fromString(data=getRSAKeys()[0])
    }
    privateKeys = {
        b'ssh-rsa': keys.Key.fromString(data=getRSAKeys()[1])
    }
    services = {
        b'ssh-userauth': userauth.SSHUserAuthServer,
        b'ssh-connection': connection.SSHConnection
    }

    def buildProtocol(self, addr):
        t = CustomSSHServerTransport(self.ourVersionString)
        t.supportedPublicKeys = self.publicKeys.keys()
        t.factory = self
        return t

class LoggingPasswordChecker:
    credentialInterfaces = [credentials.IUsernamePassword]

    def requestAvatarId(self, creds):
        log.msg(f"Login attempt - Username: {creds.username}, Password: {creds.password}")
        return defer.fail(error.UnauthorizedLogin())

def main():
    parser = argparse.ArgumentParser(description='Run a simple SSH honeypot server.')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind the SSH server to.')
    parser.add_argument('--port', type=int, default=2222, help='Port to bind the SSH server to.')
    parser.add_argument('--ssh_version', type=str, default='SSH-2.0-OpenSSH_7.4', help='Custom SSH version string to display.')
    args = parser.parse_args()

    LOG_FILE_PATH = os.path.join(script_dir, "ssh_honeypot.log")
    print(f"SSH HONEYPOT ACTIVE ON HOST: {args.host}, PORT: {args.port}")
    print(f"ALL attempts will be logged in: {LOG_FILE_PATH}")

    log_observer = textFileLogObserver(open(LOG_FILE_PATH, 'a'))
    log.startLoggingWithObserver(log_observer, setStdout=False)

    ssh_factory = SimpleSSHFactory(args.ssh_version)
    ssh_realm = SimpleSSHRealm()
    ssh_portal = portal.Portal(ssh_realm)
    ssh_portal.registerChecker(LoggingPasswordChecker())
    ssh_factory.portal = ssh_portal

    endpoint = endpoints.TCP4ServerEndpoint(reactor, args.port, interface=args.host)
    endpoint.listen(ssh_factory)
    reactor.run()

if __name__ == "__main__":
    main()
