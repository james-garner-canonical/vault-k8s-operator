"""Common test cases for the authorize-charm action."""

# ruff: noqa: D101, D102

import typing

import ops
import pytest
from ops import testing

from vault.testing.mocks import VaultCharmFixturesBase


# we inherit from VaultCharmFixturesBase to satisfy the type checker for e.g. self.mock_vault
# these attributes are only actually set by the autouse fixtures in the machine and k8s charms
# VaultCharmFixtures classes (which inherit from VaultCharmFixturesBase), meaning that the base
# class here has no runtime effect and could be replaced with e.g. type: ignore comments
class Tests(VaultCharmFixturesBase):
    ctx: testing.Context  # k8s and machine classes will provide this with their charm class
    charm_type: type[ops.CharmBase]  # likewise provided by k8s and machine subclasses

    # k8s tests will override this
    def containers(self) -> typing.Iterable[testing.Container]:
        return ()

    # machine tests will override this
    def networks(self) -> typing.Iterable[testing.Network]:
        return ()

    def test_given_unit_not_leader_when_authorize_charm_then_action_fails(self):
        state_in = testing.State(containers=self.containers(), leader=False)
        event = self.ctx.on.action("authorize-charm")
        with pytest.raises(testing.ActionFailed) as e:
            self.ctx.run(event, state=state_in)
        assert e.value.message == "This action must be run on the leader unit."

    def test_given_secret_id_not_found_when_authorize_charm_then_action_fails(self):
        state_in = testing.State(containers=self.containers(), leader=True)
        event = self.ctx.on.action("authorize-charm", params={"secret-id": "my secret id"})
        with pytest.raises(testing.ActionFailed) as e:
            self.ctx.run(event, state=state_in)
        msg = e.value.message
        assert "The secret id provided could not be found by the charm." in msg
        assert "Please grant the token secret to the charm." in msg

    def test_given_no_token_when_authorize_charm_then_action_fails(self):
        secret = testing.Secret(tracked_content={"no-token": "no token"})
        state_in = testing.State(containers=self.containers(), leader=True, secrets=[secret])
        event = self.ctx.on.action("authorize-charm", params={"secret-id": secret.id})
        with pytest.raises(testing.ActionFailed) as e:
            self.ctx.run(event, state=state_in)
        msg = e.value.message
        assert "Token not found in the secret." in msg
        assert "Please provide a valid token secret." in msg

    def test_given_ca_certificate_unavailable_when_authorize_charm_then_fails(self):
        self.mock_tls.configure_mock(**{"tls_file_available_in_charm.return_value": False})
        secret = testing.Secret(tracked_content={"token": "invalid token"})
        peer_relation = testing.PeerRelation(endpoint="vault-peers")
        state_in = testing.State(
            containers=self.containers(),
            networks=self.networks(),
            leader=True,
            secrets=[secret],
            relations=[peer_relation],
        )
        event = self.ctx.on.action("authorize-charm", params={"secret-id": secret.id})
        with pytest.raises(testing.ActionFailed) as e:
            self.ctx.run(event, state_in)
        assert e.value.message == (
            "CA certificate is not available in the charm. Something is wrong."
        )

    def test_given_invalid_token_when_authorize_charm_then_action_fails(self):
        self.mock_lib_vault.configure_mock(**{"authenticate.return_value": False})
        secret = testing.Secret(tracked_content={"token": "invalid token"})
        peer_relation = testing.PeerRelation(endpoint="vault-peers")
        state_in = testing.State(
            containers=self.containers(),
            networks=self.networks(),
            leader=True,
            secrets=[secret],
            relations=[peer_relation],
        )
        event = self.ctx.on.action("authorize-charm", params={"secret-id": secret.id})
        with pytest.raises(testing.ActionFailed) as e:
            self.ctx.run(event, state=state_in)
        assert e.value.message == (
            "The token provided is not valid."
            " Please use a Vault token with the appropriate permissions."
        )
