//! An [`Authorize`] over weirdnet-access's host-side enforcement (feature `access`).
use crate::policy::{AccessRequest, Action, Authorize, Decision};
use weirdnet_access::{Catalog, Facts, RoleSet, Settings};

/// `vault.list`
pub const LIST: &str = "vault.list";
/// `vault.read-meta`
pub const READ_META: &str = "vault.read-meta";
/// `vault.create`
pub const CREATE: &str = "vault.create";
/// `vault.rotate`
pub const ROTATE: &str = "vault.rotate";
/// `vault.delete`
pub const DELETE: &str = "vault.delete";
/// `vault.use`
pub const USE: &str = "vault.use";
/// `vault.reveal`
pub const REVEAL: &str = "vault.reveal";
/// `vault.grant`
pub const GRANT: &str = "vault.grant";
/// `vault.audit`
pub const AUDIT: &str = "vault.audit";
/// `vault.backup`
pub const BACKUP: &str = "vault.backup";
/// `vault.admin`: every vault permission.
pub const ADMIN: &str = "vault.admin";

/// The weirdnet-access permission for a vault action.
pub fn permission(action: Action) -> &'static str {
    match action {
        Action::List => LIST,
        Action::ReadMeta => READ_META,
        Action::Create => CREATE,
        Action::Rotate => ROTATE,
        Action::Delete => DELETE,
        Action::Use => USE,
        Action::Reveal => REVEAL,
        Action::Grant => GRANT,
        Action::Audit => AUDIT,
        Action::Backup => BACKUP,
    }
}

/// Add the vault permissions to `catalog`. Changing and retrieving are managing permissions
/// (never given to guests); `vault.admin` implies them all, `vault.use` and `vault.reveal`
/// imply `vault.read-meta`, which implies `vault.list`.
pub fn add_vault_permissions(catalog: &mut Catalog) -> weirdnet_access::Result<()> {
    for (name, what, managing) in [
        (LIST, "list secret metadata", false),
        (READ_META, "read a secret's metadata, versions and grants", false),
        (CREATE, "create secrets", true),
        (ROTATE, "stage, promote and roll back secret versions", true),
        (DELETE, "delete secrets", true),
        (USE, "use secrets inside the server", false),
        (REVEAL, "retrieve secret values", true),
        (GRANT, "approve identities for secrets", true),
        (AUDIT, "read the audit log", false),
        (BACKUP, "take vault snapshots", true),
        (ADMIN, "everything in the vault", true),
    ] {
        catalog.add(name, what, managing)?;
    }
    catalog.imply(READ_META, &[LIST])?;
    catalog.imply(USE, &[READ_META])?;
    catalog.imply(REVEAL, &[READ_META])?;
    catalog.imply(ADMIN, &[CREATE, ROTATE, DELETE, USE, REVEAL, GRANT, AUDIT, BACKUP])?;
    Ok(())
}

/// weirdnet-access's core catalog plus the vault permissions.
pub fn vault_catalog() -> weirdnet_access::Result<Catalog> {
    let mut c = Catalog::core();
    add_vault_permissions(&mut c)?;
    Ok(c)
}

/// Decides each request with weirdnet-access `enforce::decide`: identity, visibility,
/// membership, then role. The app supplies the [`Facts`] for each request (who the caller is,
/// whether they own the resource, their membership role).
pub struct AccessAuthorizer<F> {
    catalog: Catalog,
    roles: RoleSet,
    settings: Settings,
    facts: F,
}

impl<F> std::fmt::Debug for AccessAuthorizer<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessAuthorizer").field("roles", &self.roles).field("settings", &self.settings).finish_non_exhaustive()
    }
}

impl<F> AccessAuthorizer<F>
where
    F: Fn(&AccessRequest<'_>) -> Facts + Send + Sync,
{
    /// An authorizer over `catalog` (see [`vault_catalog`]), `roles` and `settings`.
    pub fn new(catalog: Catalog, roles: RoleSet, settings: Settings, facts: F) -> Self {
        AccessAuthorizer { catalog, roles, settings, facts }
    }
}

impl<F> Authorize for AccessAuthorizer<F>
where
    F: Fn(&AccessRequest<'_>) -> Facts + Send + Sync,
{
    fn authorize(&self, request: &AccessRequest<'_>) -> Decision {
        let facts = (self.facts)(request);
        match weirdnet_access::decide(&self.catalog, &self.roles, self.settings, &facts, permission(request.action)) {
            weirdnet_access::Decision::Allow { .. } => Decision::Allow,
            weirdnet_access::Decision::NotFound => Decision::deny("not found"),
            weirdnet_access::Decision::JoinFirst => Decision::deny("membership required"),
            weirdnet_access::Decision::Denied(why) => Decision::deny(why),
        }
    }
}
