"""Common test cases for the authorize-charm action."""

# ruff: noqa: D101, D102

import typing

import pytest
from ops import testing

from vault.testing.mocks import VaultCharmFixturesBase


# we inherit from VaultCharmFixturesBase to satisfy the type checker for e.g. self.mock_vault
# these attributes are only actually set by the autouse fixtures in the machine and k8s charms
# VaultCharmFixtures classes (which inherit from VaultCharmFixturesBase), meaning that the base
# class here has no runtime effect and could be replaced with e.g. type: ignore comments
class Tests(VaultCharmFixturesBase):
    ctx: testing.Context  # k8s and machine classes will provide this with their charm class

    # k8s tests will override this
    def containers(self) -> typing.Iterable[testing.Container]:
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
        self.mock_vault.configure_mock(**{"authenticate.return_value": False})
        secret = testing.Secret(tracked_content={"no-token": "no token"})  # user provided
        state_in = testing.State(containers=self.containers(), leader=True, secrets=[secret])
        event = self.ctx.on.action("authorize-charm", params={"secret-id": secret.id})
        with pytest.raises(testing.ActionFailed) as e:
            self.ctx.run(event, state=state_in)
        msg = e.value.message
        assert "Token not found in the secret." in msg
        assert "Please provide a valid token secret." in msg
