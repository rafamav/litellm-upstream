//! A team membership as the database holds it, in the shape the auth cache holds it.

use std::sync::Arc;

use litellm_redis_store::auth_cache::{ExcludedIfNone, MemberEntry, TeamMembershipEntry};
use litellm_repositories::{
    JoinBudget, MappedClaim, MemberAdd, MemberBudget, MemberRemove, RosterRole, Side,
    TeamMembership, TeamMembershipRepository,
};

use crate::{Error, budget::budget_full_entry, error::within, member::roster};

/// The team membership as the database holds it, in the shape the auth cache holds it: the row
/// with its budget.
pub struct TeamMembershipDatabase {
    memberships: Arc<TeamMembershipRepository>,
}

impl TeamMembershipDatabase {
    pub fn new(memberships: Arc<TeamMembershipRepository>) -> Self {
        Self { memberships }
    }

    /// `user_id`'s membership of `team_id`, or `None` when the user is not a member.
    pub async fn team_membership(
        &self,
        user_id: &str,
        team_id: &str,
        side: Side,
    ) -> Result<Option<TeamMembershipEntry>, Error> {
        self.memberships
            .find_with_budget(user_id, team_id, side)
            .await?
            .map(team_membership_entry)
            .transpose()
    }

    /// Adds `user_id` to `team_id` as a `user` with `budget`, in the repository's one transaction.
    /// Python recaches nothing after it: it evicts the team, its alias, the user and the
    /// membership, and reads the roster for the team members gauge and the audit log, so the
    /// roster as stored is what comes back.
    pub async fn add_member(
        &self,
        user_id: &str,
        team_id: &str,
        budget: MemberBudget<'_>,
    ) -> Result<MemberAdded, Error> {
        member_added(
            self.memberships
                .add_member(user_id, team_id, budget)
                .await?,
        )
    }

    /// [`Self::add_member`] with the member's `role` and a budget that may carry a cap, as
    /// `add_new_user_to_default_team` adds a user `user_id_upsert` just created to each team in
    /// `default_internal_user_params.teams`. Which teams, which role and which budget are the
    /// host's to resolve, as `_memberships_on_team_member_budget` and `resolve_member_budget_id`
    /// do.
    pub async fn add_member_as(
        &self,
        user_id: &str,
        team_id: &str,
        role: RosterRole,
        budget: JoinBudget<'_>,
    ) -> Result<MemberAdded, Error> {
        member_added(
            self.memberships
                .add_member_as(user_id, team_id, role, budget)
                .await?,
        )
    }

    /// Removes `user_id` from `team_id`, as the JWT team sync does through `team_member_delete`
    /// for a team that left the token, in the repository's one transaction. What comes back is
    /// what Python evicts and audits after it: the roster before and after, the hashes of the
    /// user's deleted keys in the team and the JWT claims mapped to them. The deleted keys
    /// themselves are in `LiteLLM_DeletedVerificationToken`.
    pub async fn remove_member(
        &self,
        user_id: &str,
        team_id: &str,
    ) -> Result<MemberRemoved, Error> {
        Ok(
            match self.memberships.remove_member(user_id, team_id).await? {
                MemberRemove::Removed(removed) => MemberRemoved::Removed {
                    roster_before: roster(&removed.roster_before.to_string())?,
                    roster_after: roster(&removed.roster_after.to_string())?,
                    deleted_tokens: removed.deleted_tokens,
                    mapped_claims: removed.mapped_claims,
                },
                MemberRemove::NotMember => MemberRemoved::NotMember,
                MemberRemove::TeamMissing => MemberRemoved::TeamMissing,
            },
        )
    }
}

fn member_added(added: MemberAdd) -> Result<MemberAdded, Error> {
    Ok(match added {
        MemberAdd::Added(added) => MemberAdded::Added {
            roster: roster(&added.roster.to_string())?,
        },
        MemberAdd::AlreadyMember => MemberAdded::AlreadyMember,
        MemberAdd::TeamMissing => MemberAdded::TeamMissing,
        MemberAdd::UserMissing => MemberAdded::UserMissing,
    })
}

/// How a member add ended. Only `Added` wrote anything, and it holds the team's roster as
/// stored, the new member last.
#[derive(Debug, PartialEq)]
pub enum MemberAdded {
    Added { roster: Vec<MemberEntry> },
    AlreadyMember,
    TeamMissing,
    UserMissing,
}

/// How a member removal ended. Only `Removed` wrote anything.
#[derive(Debug, PartialEq)]
pub enum MemberRemoved {
    Removed {
        roster_before: Vec<MemberEntry>,
        roster_after: Vec<MemberEntry>,
        deleted_tokens: Vec<String>,
        mapped_claims: Vec<MappedClaim>,
    },
    /// Neither the roster nor the user's teams list the team, which Python's sync skips.
    NotMember,
    TeamMissing,
}

/// What `LiteLLM_TeamMembership.model_dump(mode="json")` holds for `membership`, or the column
/// the model would refuse the row for.
fn team_membership_entry(membership: TeamMembership) -> Result<TeamMembershipEntry, Error> {
    let TeamMembership {
        user_id,
        team_id,
        budget_id,
        spend,
        rollover_credit,
        total_spend,
        litellm_budget_table,
    } = membership;
    Ok(TeamMembershipEntry {
        user_id,
        team_id,
        budget_id,
        spend: Some(spend),
        total_spend: Some(total_spend),
        rollover_credit: ExcludedIfNone(rollover_credit),
        litellm_budget_table: litellm_budget_table
            .map(|budget| budget_full_entry(budget.0))
            .transpose()
            .map_err(within("litellm_budget_table"))?,
        unread: Vec::new(),
    })
}
