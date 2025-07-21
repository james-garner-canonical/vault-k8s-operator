#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import ops.testing as testing
import pytest
import vault.testing.authorize_action
from ops.testing import ActionFailed
from vault.vault_client import AuditDeviceType

from fixtures import VaultCharmFixtures


class TestCharmAuthorizeAction(VaultCharmFixtures, vault.testing.authorize_action.Tests):
    def networks(self):
        bind_address = testing.BindAddress([testing.Address("1.2.1.2")])
        return [testing.Network("vault-peers", bind_addresses=[bind_address])]

    def relations(self):
        return [testing.PeerRelation(endpoint="vault-peers")]

    def test_given_api_address_unavailable_when_authorize_charm_then_fails(self):
        # Only the machine charm will raise this error, as the k8s charm always returns an address
        self.mock_vault.configure_mock(**{"authenticate.return_value": False})
        secret = testing.Secret(tracked_content={"token": "my token"})
        state_in = testing.State(leader=True, secrets=[secret])
        event = self.ctx.on.action("authorize-charm", params={"secret-id": secret.id})
        with pytest.raises(ActionFailed) as e:
            self.ctx.run(event, state_in)
        assert e.value.message == "API address is not available."

    def test_given_when_authorize_charm_then_charm_is_authorized(self):
        mock_vault = self.mock_lib_vault
        mock_vault.configure_mock(
            **{
                "authenticate.return_value": True,
                "create_or_update_approle.return_value": "my-role-id",
                "generate_role_secret_id.return_value": "my-secret-id",
            },
        )
        user_provided_secret = testing.Secret(
            tracked_content={"token": "my token"},
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            leader=True,
            secrets=[user_provided_secret],
            relations=[peer_relation],
            networks={
                testing.Network(
                    "vault-peers",
                    bind_addresses=[testing.BindAddress([testing.Address("1.2.1.2")])],
                )
            },
        )
        out_state = self.ctx.run(
            self.ctx.on.action("authorize-charm", params={"secret-id": user_provided_secret.id}),
            state_in,
        )

        mock_vault.enable_audit_device.assert_called_once_with(
            device_type=AuditDeviceType.FILE, path="stdout"
        )
        mock_vault.enable_approle_auth_method.assert_called_once()
        mock_vault.create_or_update_policy_from_file.assert_called_once_with(
            name="charm-access",
            path="src/templates/charm_policy.hcl",
        )
        mock_vault.create_or_update_approle.assert_called_once_with(
            name="charm",
            policies=["charm-access", "default"],
            token_ttl="1h",
            token_max_ttl="1h",
        )
        assert self.ctx.action_results == {
            "result": "Charm authorized successfully. You may now remove the secret."
        }
        assert out_state.get_secret(label="vault-approle-auth-details").tracked_content == {
            "role-id": "my-role-id",
            "secret-id": "my-secret-id",
        }
