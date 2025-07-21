"""Common test cases for the authorize-charm action."""

# ruff: noqa: D101, D102

import typing

import pytest
from ops import testing


class Tests:
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
