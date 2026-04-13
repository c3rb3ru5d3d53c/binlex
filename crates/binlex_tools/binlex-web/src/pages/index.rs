use crate::assets::{LOGO, SCRIPT, STYLES};
use crate::{AuthUserProfile, PageData, build_search_response};
use askama::Template;

#[derive(Template)]
#[template(path = "pages/index.html")]
struct IndexTemplate<'a> {
    styles: &'a str,
    script: &'a str,
    logo: &'a str,
    bootstrap: String,
    auth_header_html: String,
    auth_modal_html: String,
    server_status_badge: String,
    index_status_badge: String,
    database_status_badge: String,
    upload_button_enabled: bool,
    uploaded_sha256: Option<&'a str>,
    corpora_options_json: String,
    architecture_options_json: String,
    collection_options_json: String,
    query_completion_specs_json: String,
    query: &'a str,
    top_k: usize,
    page: usize,
    upload_modal_html: String,
}

#[derive(Template)]
#[template(path = "pages/partials/status_badge.html")]
struct StatusBadgeTemplate<'a> {
    label: &'a str,
    value: &'a str,
    healthy: bool,
}

#[derive(Template)]
#[template(path = "pages/partials/upload_modal.html")]
struct UploadModalTemplate {
    format_select_html: String,
    has_corpus_picker: bool,
    architecture_select_html: String,
    corpus_picker_html: Option<String>,
    tag_picker_html: String,
}

#[derive(Template)]
#[template(path = "pages/partials/single_select.html")]
struct SingleSelectTemplate<'a> {
    name: &'a str,
    label: &'a str,
    selected: &'a str,
    options: &'a [String],
    search_enabled: bool,
}

#[derive(Template)]
#[template(path = "pages/partials/upload_corpus_picker.html")]
struct UploadCorpusPickerTemplate {
    options_json: String,
    selected_json: String,
    default_corpus: String,
    locked: bool,
}

#[derive(Template)]
#[template(path = "pages/partials/upload_tag_picker.html")]
struct UploadTagPickerTemplate {
    options_json: String,
    selected_json: String,
}

pub(crate) fn render_page(data: &PageData) -> String {
    let template = IndexTemplate {
        styles: STYLES,
        script: SCRIPT,
        logo: LOGO,
        bootstrap: render_search_bootstrap(data),
        auth_header_html: render_auth_header(data),
        auth_modal_html: render_auth_modals(data),
        server_status_badge: status_badge(
            "Server",
            if data.status.server_ok {
                "connected"
            } else {
                "disconnected"
            },
            data.status.server_ok,
        ),
        index_status_badge: status_badge("Index", "local", data.status.index_ok),
        database_status_badge: status_badge("Database", "local", data.status.database_ok),
        upload_button_enabled: data.upload_button_enabled,
        uploaded_sha256: data.uploaded_sha256.as_deref(),
        corpora_options_json: serde_json::to_string(&data.corpora_options)
            .unwrap_or_else(|_| "[]".to_string()),
        architecture_options_json: serde_json::to_string(&data.architecture_options)
            .unwrap_or_else(|_| "[]".to_string()),
        collection_options_json: serde_json::to_string(&data.collection_options)
            .unwrap_or_else(|_| "[]".to_string()),
        query_completion_specs_json: serde_json::to_string(&data.query_completion_specs)
            .unwrap_or_else(|_| "[]".to_string()),
        query: &data.query,
        top_k: data.top_k,
        page: data.page,
        upload_modal_html: if data.uploads_enabled {
            render_upload_modal(data)
        } else {
            String::new()
        },
    };
    template.render().unwrap_or_else(|_| String::new())
}

fn render_search_bootstrap(data: &PageData) -> String {
    let value =
        serde_json::to_string(&build_search_response(data)).unwrap_or_else(|_| "{}".to_string());
    let escaped = value.replace('<', "\\u003c");
    let auth_user_json =
        serde_json::to_string(&data.auth_user).unwrap_or_else(|_| "null".to_string());
    format!(
        "window.__BINLEX_SEARCH_DATA__ = {}; window.__BINLEX_AUTH__ = {{ can_write: {}, role: \"{}\", two_factor_required: {} }}; window.__BINLEX_CURRENT_USER__ = {};",
        escaped,
        if data.auth_user.is_some() {
            "true"
        } else {
            "false"
        },
        data.auth_user
            .as_ref()
            .map(|user| html_escape(&user.role))
            .unwrap_or_default(),
        if data.auth_two_factor_required {
            "true"
        } else {
            "false"
        },
        auth_user_json.replace('<', "\\u003c")
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn auth_avatar_label(user: &AuthUserProfile) -> String {
    if let Some(picture) = &user.profile_picture {
        if !picture.trim().is_empty() {
            return format!(
                "<img src=\"{}\" alt=\"{}\">",
                html_escape(picture),
                html_escape(&user.username)
            );
        }
    }
    let initial = user.username.chars().next().unwrap_or('U');
    format!("<span>{}</span>", html_escape(&initial.to_string()))
}

fn render_auth_header(data: &PageData) -> String {
    if data.auth_bootstrap_required {
        return "<div class=\"auth-header\"><span class=\"auth-pill\">Setup Required</span></div>"
            .to_string();
    }
    if let Some(user) = &data.auth_user {
        let users_button = if user.role == "admin" {
            "<button type=\"button\" class=\"auth-menu-item\" onclick=\"openUsersModal()\">Administration</button>"
                .to_string()
        } else {
            String::new()
        };
        return format!(
            "<div class=\"auth-header\"><button type=\"button\" class=\"auth-trigger\" onclick=\"toggleAuthMenu()\"><span class=\"auth-avatar\">{avatar}</span><span class=\"auth-trigger-label\">{username}</span><span class=\"auth-trigger-caret\">▾</span></button><div class=\"auth-menu\" id=\"auth-menu\" hidden><div class=\"auth-menu-summary\"><span class=\"auth-avatar auth-menu-avatar\">{avatar}</span><div class=\"auth-menu-summary-copy\"><strong>{username}</strong><span>{role}</span></div></div><button type=\"button\" class=\"auth-menu-item\" onclick=\"openProfileModal()\">Profile</button>{users}<button type=\"button\" class=\"auth-menu-item\" onclick=\"logout()\">Logout</button></div></div>",
            avatar = auth_avatar_label(user),
            username = html_escape(&user.username),
            role = html_escape(&user.role),
            users = users_button
        );
    }
    format!(
        "<div class=\"auth-header\"><button type=\"button\" class=\"auth-trigger\" onclick=\"toggleAuthMenu()\"><span class=\"auth-avatar\"><span>g</span></span><span class=\"auth-trigger-label\">guest</span><span class=\"auth-trigger-caret\">▾</span></button><div class=\"auth-menu\" id=\"auth-menu\" hidden><div class=\"auth-menu-summary\"><strong>guest</strong><span>read-only</span></div><button type=\"button\" class=\"auth-menu-item\" onclick=\"openAuthModal('login')\">Login</button></div></div>"
    )
}

fn render_auth_modals(data: &PageData) -> String {
    let bootstrap_hidden = if data.auth_bootstrap_required {
        ""
    } else {
        " hidden"
    };
    let auth_hidden = if data.auth_bootstrap_required {
        " hidden"
    } else {
        ""
    };
    let register_tab = if data.auth_registration_enabled {
        "<button type=\"button\" class=\"upload-metadata-tab\" data-auth-tab=\"register\" onclick=\"toggleAuthTab('register')\">Register</button>"
    } else {
        ""
    };
    let user = data.auth_user.as_ref();
    let profile_username = user
        .map(|value| html_escape(&value.username))
        .unwrap_or_default();
    let profile_role = user
        .map(|value| html_escape(&value.role))
        .unwrap_or_default();
    let profile_key = user
        .map(|value| html_escape(&value.key))
        .unwrap_or_default();
    let profile_two_factor_enabled = user.map(|value| value.two_factor_enabled).unwrap_or(false);
    let profile_two_factor_required = user.map(|value| value.two_factor_required).unwrap_or(false);
    let profile_two_factor_status = if profile_two_factor_enabled {
        "Enabled"
    } else if profile_two_factor_required {
        "Required on next sign in"
    } else {
        "Disabled"
    };
    let profile_avatar = if let Some(value) = user {
        auth_avatar_label(value)
    } else {
        "<span>u</span>".to_string()
    };
    let user_role_options = vec!["user".to_string(), "admin".to_string()];
    let user_role_select_html =
        render_single_select_dropdown("role", "Role", &user_role_options, "user", false);
    format!(
        r#"
<div class="modal-backdrop auth-modal-backdrop" id="bootstrap-modal"{bootstrap_hidden}>
  <div class="modal-card auth-card bootstrap-card" role="dialog" aria-modal="true" aria-label="Create Admin">
    <div class="modal-header"><h2>Create Admin</h2></div>
    <p class="modal-tip">Create the first admin account to finish setting up Binlex Web.</p>
    <form class="modal-grid auth-form bootstrap-form" data-live-validation="create" onsubmit="submitBootstrap(event)">
      <div class="profile-security-heading">Account</div>
      <label class="modal-field"><span>Admin Username</span><input class="menu-search" name="username" required autocomplete="username"></label>
      <div class="auth-field-feedback" data-feedback-for="username"></div>
      <div class="profile-security-heading">Security</div>
      <label class="modal-field"><span>Password</span><input class="menu-search" name="password" type="password" required autocomplete="new-password"></label>
      <div class="auth-field-feedback" data-feedback-for="password"></div>
      <label class="modal-field"><span>Confirm Password</span><input class="menu-search" name="password_confirm" type="password" required autocomplete="new-password"></label>
      <div class="auth-field-feedback" data-feedback-for="password_confirm"></div>
      <div class="profile-key-note bootstrap-note">This admin account will be required to enroll in 2FA before setup is complete.</div>
      <div class="modal-actions bootstrap-actions"><span class="auth-form-error" id="bootstrap-error"></span><button class="primary" type="submit">Create Admin</button></div>
    </form>
  </div>
</div>

<div class="modal-backdrop auth-modal-backdrop" id="auth-modal"{auth_hidden} hidden>
  <div class="modal-card auth-card" role="dialog" aria-modal="true" aria-label="Sign In">
    <div class="modal-header"><h2>Account</h2><button type="button" class="secondary auth-close" onclick="closeAuthModal()">Close</button></div>
    <div class="upload-metadata-tab-row auth-tab-row">
      <button type="button" class="upload-metadata-tab is-active" data-auth-tab="login" onclick="toggleAuthTab('login')">Login</button>
      {register_tab}
      <button type="button" class="upload-metadata-tab" data-auth-tab="reset" onclick="toggleAuthTab('reset')">Reset Password</button>
    </div>
    <form class="modal-grid auth-form" id="auth-login-form" data-auth-panel="login" onsubmit="submitLogin(event)">
      <label class="modal-field"><span>Username</span><input class="menu-search" name="username" required autocomplete="username"></label>
      <label class="modal-field"><span>Password</span><input class="menu-search" name="password" type="password" required autocomplete="current-password"></label>
      <div class="modal-actions"><span class="auth-form-error" id="auth-login-error"></span><button class="primary" type="submit">Sign In</button></div>
    </form>
    <form class="modal-grid auth-form" id="auth-register-form" data-auth-panel="register" data-live-validation="create" onsubmit="submitRegister(event)" hidden>
      <label class="modal-field"><span>Username</span><input class="menu-search" name="username" required autocomplete="username"></label>
      <div class="auth-field-feedback" data-feedback-for="username"></div>
      <label class="modal-field"><span>Password</span><input class="menu-search" name="password" type="password" required autocomplete="new-password"></label>
      <div class="auth-field-feedback" data-feedback-for="password"></div>
      <label class="modal-field"><span>Confirm Password</span><input class="menu-search" name="password_confirm" type="password" required autocomplete="new-password"></label>
      <div class="auth-field-feedback" data-feedback-for="password_confirm"></div>
      <input type="hidden" name="captcha_id" id="auth-register-captcha-id">
      <div class="modal-field captcha-field">
        <span>Captcha</span>
        <div class="captcha-frame">
          <img id="auth-register-captcha-image" class="captcha-image" alt="Registration captcha">
          <button type="button" class="secondary captcha-refresh" onclick="refreshRegisterCaptcha()">Refresh</button>
        </div>
      </div>
      <label class="modal-field"><span>Captcha Answer</span><input class="menu-search" name="captcha_answer" required autocomplete="off" autocapitalize="characters" spellcheck="false"></label>
      <div class="modal-actions"><span class="auth-form-error" id="auth-register-error"></span><button class="primary" type="submit">Create Account</button></div>
    </form>
    <form class="modal-grid auth-form" id="auth-reset-form" data-auth-panel="reset" data-live-validation="reset" onsubmit="submitPasswordReset(event)" hidden>
      <label class="modal-field"><span>Username</span><input class="menu-search" name="username" required autocomplete="username"></label>
      <div class="auth-field-feedback" data-feedback-for="username"></div>
      <label class="modal-field"><span>Recovery Code</span><input class="menu-search" name="recovery_code" required autocomplete="one-time-code"></label>
      <label class="modal-field"><span>New Password</span><input class="menu-search" name="new_password" type="password" required autocomplete="new-password"></label>
      <div class="auth-field-feedback" data-feedback-for="password"></div>
      <label class="modal-field"><span>Confirm Password</span><input class="menu-search" name="password_confirm" type="password" required autocomplete="new-password"></label>
      <div class="auth-field-feedback" data-feedback-for="password_confirm"></div>
      <input type="hidden" name="captcha_id" id="auth-reset-captcha-id">
      <div class="modal-field captcha-field">
        <span>Captcha</span>
        <div class="captcha-frame">
          <img id="auth-reset-captcha-image" class="captcha-image" alt="Password reset captcha">
          <button type="button" class="secondary captcha-refresh" onclick="refreshResetCaptcha()">Refresh</button>
        </div>
      </div>
      <label class="modal-field"><span>Captcha Answer</span><input class="menu-search" name="captcha_answer" required autocomplete="off" autocapitalize="characters" spellcheck="false"></label>
      <div class="modal-actions"><span class="auth-form-error" id="auth-reset-error"></span><button class="primary" type="submit">Reset Password</button></div>
    </form>
  </div>
</div>

<div class="modal-backdrop auth-modal-backdrop" id="profile-modal" hidden>
  <div class="modal-card auth-card" role="dialog" aria-modal="true" aria-label="Profile">
    <div class="modal-header"><h2>Profile</h2><button type="button" class="secondary auth-close" onclick="closeProfileModal()">Close</button></div>
    <div class="upload-metadata-tab-row auth-tab-row profile-tab-row">
      <button type="button" class="upload-metadata-tab is-active" data-profile-tab-button="account" onclick="toggleProfileTab('account')">Account</button>
      <button type="button" class="upload-metadata-tab" data-profile-tab-button="security" onclick="toggleProfileTab('security')">Security</button>
      <button type="button" class="upload-metadata-tab" data-profile-tab-button="key" onclick="toggleProfileTab('key')">API Key</button>
      <button type="button" class="upload-metadata-tab" data-profile-tab-button="danger" onclick="toggleProfileTab('danger')">Danger</button>
    </div>
    <div class="modal-grid profile-panel is-active" data-profile-panel="account">
      <div class="modal-field">
        <span>Avatar</span>
        <div class="profile-avatar-field">
          <button type="button" class="auth-avatar profile-avatar-preview profile-avatar-button" id="profile-avatar-preview" onclick="chooseProfilePicture()" title="Click to choose an image" aria-label="Click to choose an image">
            {profile_avatar}
            <span class="profile-avatar-camera" aria-hidden="true">📷</span>
          </button>
          <div class="profile-avatar-controls">
            <input class="hidden-file" id="profile-picture-file" type="file" accept="image/png,image/jpeg,image/webp" onchange="updateProfilePictureSelection()">
            <div class="modal-actions">
              <span class="auth-form-error" id="profile-picture-error"></span>
              <button type="button" class="secondary" onclick="deleteProfilePicture()">Delete Avatar</button>
            </div>
          </div>
        </div>
      </div>
      <label class="modal-field"><span>Username</span><input class="menu-search" value="{profile_username}" disabled></label>
      <label class="modal-field"><span>Role</span><input class="menu-search" value="{profile_role}" disabled></label>
    </div>
    <div class="modal-grid profile-panel" data-profile-panel="security" data-live-validation="profile-password" hidden>
      <div class="profile-security-block">
        <div class="profile-security-heading">Two-Factor Authentication</div>
        <div class="profile-key-note" id="profile-2fa-status">Status: {profile_two_factor_status}</div>
        <div class="modal-actions">
          <span class="auth-form-error" id="profile-2fa-error"></span>
          <button type="button" class="secondary" id="profile-2fa-setup-button" onclick="openTwoFactorSetupModal('profile')"{profile_two_factor_setup_hidden}>Enable 2FA</button>
          <button type="button" class="secondary" id="profile-2fa-disable-button" onclick="openTwoFactorDisableModal()"{profile_two_factor_disable_hidden}>Disable 2FA</button>
        </div>
      </div>
      <label class="modal-field"><span>Current Password</span><input class="menu-search" id="profile-password-current" type="password" autocomplete="current-password"></label>
      <label class="modal-field"><span>New Password</span><input class="menu-search" id="profile-password-next" name="new_password" type="password" autocomplete="new-password"></label>
      <div class="auth-field-feedback" data-feedback-for="password"></div>
      <label class="modal-field"><span>Confirm New Password</span><input class="menu-search" id="profile-password-confirm" name="password_confirm" type="password" autocomplete="new-password"></label>
      <div class="auth-field-feedback" data-feedback-for="password_confirm"></div>
      <div class="modal-actions"><span class="auth-form-error" id="profile-password-error"></span><button type="button" class="secondary" onclick="changeProfilePassword()">Change Password</button></div>
      <div class="profile-key-note">Regenerating recovery codes invalidates the previous set.</div>
      <div class="modal-actions"><span class="auth-form-error" id="profile-recovery-error"></span><button type="button" class="secondary" onclick="regenerateProfileRecoveryCodes()">Regenerate Recovery Codes</button></div>
    </div>
    <div class="modal-grid profile-panel" data-profile-panel="key" hidden>
      <label class="modal-field">
        <span>API Key</span>
        <div class="profile-key-wrap">
          <input class="menu-search profile-key-input" id="profile-key-output" type="password" value="{profile_key}" placeholder="Regenerate to reveal a new API key." readonly data-secret="{profile_key}">
          <button type="button" class="symbol-picker-copy profile-key-copy" id="profile-key-copy" onclick="copyProfileKey()"{profile_key_disabled}>Copy</button>
          <button type="button" class="secondary recovery-codes-visibility profile-key-toggle" id="profile-key-toggle" onclick="toggleProfileKeyVisibility()"{profile_key_disabled} aria-label="Show API key" title="Show API key"><span class="recovery-codes-eye" aria-hidden="true">👁</span></button>
        </div>
      </label>
      <div class="profile-key-note">Use Copy to copy the current key, or Show to reveal it.</div>
      <div class="modal-actions"><span class="auth-form-error" id="profile-key-error"></span><button type="button" class="secondary" onclick="regenerateProfileKey()">Regenerate API Key</button></div>
    </div>
    <div class="modal-grid profile-panel" data-profile-panel="danger" hidden>
      <label class="modal-field"><span>Current Password</span><input class="menu-search" id="profile-delete-password" type="password" autocomplete="current-password"></label>
      <div class="profile-key-note">This permanently deletes your account.</div>
      <div class="modal-actions"><span class="auth-form-error" id="profile-delete-error"></span><button type="button" class="secondary danger-button" onclick="deleteProfile()">Delete Account</button></div>
    </div>
  </div>
</div>

<div class="modal-backdrop auth-modal-backdrop" id="users-modal" hidden>
  <div class="modal-card auth-card users-card" role="dialog" aria-modal="true" aria-label="Users">
    <div class="modal-header"><h2>Administration</h2><button type="button" class="secondary auth-close" onclick="closeUsersModal()">Close</button></div>
    <div class="upload-metadata-tab-row auth-tab-row profile-tab-row">
      <button type="button" class="upload-metadata-tab is-active" data-users-tab-button="search" onclick="toggleUsersTab('search')">Users</button>
      <button type="button" class="upload-metadata-tab" data-users-tab-button="create" onclick="toggleUsersTab('create')">Create User</button>
      <button type="button" class="upload-metadata-tab" data-users-tab-button="corpora" onclick="toggleUsersTab('corpora')">Corpora</button>
      <button type="button" class="upload-metadata-tab" data-users-tab-button="tags" onclick="toggleUsersTab('tags')">Tags</button>
      <button type="button" class="upload-metadata-tab" data-users-tab-button="symbols" onclick="toggleUsersTab('symbols')">Symbols</button>
      <button type="button" class="upload-metadata-tab" data-users-tab-button="comments" onclick="toggleUsersTab('comments')">Comments</button>
    </div>
    <div class="modal-grid users-panel is-active" data-users-panel="search">
      <div class="modal-actions"><input class="menu-search" id="users-search-input" placeholder="Search users" oninput="loadUsers()"></div>
      <div class="users-summary users-summary-row"><span id="users-summary">Showing 0 of 0</span><span class="auth-form-error users-search-error" id="users-search-error"></span></div>
      <div id="users-list" class="users-list"></div>
    </div>
    <form class="modal-grid auth-form users-create-form users-panel" data-users-panel="create" data-live-validation="create" onsubmit="createUser(event)" hidden>
      <label class="modal-field"><span>Username</span><input class="menu-search" name="username" required></label>
      <div class="auth-field-feedback" data-feedback-for="username"></div>
      <label class="modal-field"><span>Password</span><input class="menu-search" name="password" type="password" required></label>
      <div class="auth-field-feedback" data-feedback-for="password"></div>
      <label class="modal-field"><span>Confirm Password</span><input class="menu-search" name="password_confirm" type="password" required></label>
      <div class="auth-field-feedback" data-feedback-for="password_confirm"></div>
      <div class="modal-field users-create-role-field">{user_role_select_html}</div>
      <div class="modal-actions"><span class="auth-form-error" id="users-create-error"></span><button class="primary" type="submit">Create User</button></div>
    </form>
    <div class="modal-grid users-panel" data-users-panel="corpora" hidden>
      <div class="metadata-admin-search-wrap"><input class="menu-search metadata-admin-search metadata-admin-search-has-action" id="admin-corpora-search-input" placeholder="Search corpora" oninput="loadAdminMetadata('corpora')"><button type="button" class="upload-corpus-create-inline metadata-admin-create-inline" id="admin-corpora-create-button" onclick="createAdminMetadata('corpora')" disabled>Create</button></div>
      <div class="users-summary users-summary-row"><span id="admin-corpora-summary">Showing 0 of 0</span><span class="auth-form-error users-search-error" id="admin-corpora-error"></span></div>
      <div id="admin-corpora-list" class="users-list admin-metadata-list"></div>
    </div>
    <div class="modal-grid users-panel" data-users-panel="tags" hidden>
      <div class="metadata-admin-search-wrap"><input class="menu-search metadata-admin-search metadata-admin-search-has-action" id="admin-tags-search-input" placeholder="Search tags" oninput="loadAdminMetadata('tags')"><button type="button" class="upload-corpus-create-inline metadata-admin-create-inline" id="admin-tags-create-button" onclick="createAdminMetadata('tags')" disabled>Create</button></div>
      <div class="users-summary users-summary-row"><span id="admin-tags-summary">Showing 0 of 0</span><span class="auth-form-error users-search-error" id="admin-tags-error"></span></div>
      <div id="admin-tags-list" class="users-list admin-metadata-list"></div>
    </div>
    <div class="modal-grid users-panel" data-users-panel="symbols" hidden>
      <div class="metadata-admin-search-wrap"><input class="menu-search metadata-admin-search metadata-admin-search-has-action" id="admin-symbols-search-input" placeholder="Search symbols" oninput="loadAdminMetadata('symbols')"><button type="button" class="upload-corpus-create-inline metadata-admin-create-inline" id="admin-symbols-create-button" onclick="createAdminMetadata('symbols')" disabled>Create</button></div>
      <div class="users-summary users-summary-row"><span id="admin-symbols-summary">Showing 0 of 0</span><span class="auth-form-error users-search-error" id="admin-symbols-error"></span></div>
      <div id="admin-symbols-list" class="users-list admin-metadata-list"></div>
    </div>
    <div class="modal-grid users-panel" data-users-panel="comments" hidden>
      <div class="modal-actions"><input class="menu-search" id="admin-comments-search-input" placeholder="Search comments" oninput="loadAdminComments()"></div>
      <div class="users-summary users-summary-row"><span id="admin-comments-summary">Showing 0 of 0</span><span class="auth-form-error users-search-error" id="admin-comments-error"></span></div>
      <div id="admin-comments-list" class="users-list admin-comments-list"></div>
    </div>
  </div>
</div>

<div class="modal-backdrop auth-modal-backdrop" id="recovery-codes-modal" hidden>
  <div class="modal-card auth-card recovery-codes-card" role="dialog" aria-modal="true" aria-label="Recovery Codes">
    <div class="modal-header"><h2 id="recovery-codes-title">Recovery Codes</h2><button type="button" class="secondary auth-close" onclick="closeRecoveryCodesModal()">Close</button></div>
    <p class="modal-tip" id="recovery-codes-description">Save these recovery codes somewhere secure. Each code can be used once to reset your password.</p>
    <div class="recovery-codes-box">
      <pre class="recovery-codes-output" id="recovery-codes-output"></pre>
      <div class="recovery-codes-actions">
        <button type="button" class="secondary recovery-codes-copy" id="recovery-codes-copy" onclick="copyRecoveryCodes()">Copy</button>
        <button type="button" class="secondary recovery-codes-visibility" id="recovery-codes-toggle" onclick="toggleRecoveryCodesVisibility()" aria-label="Show recovery codes" title="Show recovery codes"><span class="recovery-codes-eye" aria-hidden="true">👁</span></button>
      </div>
    </div>
  </div>
</div>

<div class="modal-backdrop auth-modal-backdrop" id="profile-picture-crop-modal" hidden>
  <div class="modal-card auth-card profile-picture-crop-card" role="dialog" aria-modal="true" aria-label="Crop Avatar">
    <div class="modal-header"><h2>Crop Avatar</h2><button type="button" class="secondary auth-close" onclick="closeProfilePictureCropModal()">Close</button></div>
    <p class="modal-tip">Drag the image to reposition it and use zoom to frame your avatar.</p>
    <div class="profile-picture-crop-stage" id="profile-picture-crop-stage">
      <img id="profile-picture-crop-image" class="profile-picture-crop-image" alt="Avatar crop preview" draggable="false">
      <div class="profile-picture-crop-mask"></div>
    </div>
    <label class="modal-field">
      <span>Zoom</span>
      <input id="profile-picture-crop-zoom" class="profile-picture-crop-zoom" type="range" min="1" max="4" step="0.01" value="1" oninput="setProfilePictureCropZoom(this.value)">
    </label>
    <div class="modal-actions">
      <span class="auth-form-error" id="profile-picture-crop-error"></span>
      <button type="button" class="secondary" onclick="saveProfilePicture()">Save Avatar</button>
    </div>
  </div>
</div>

<div class="modal-backdrop auth-modal-backdrop" id="two-factor-login-modal" hidden>
  <div class="modal-card auth-card recovery-codes-card" role="dialog" aria-modal="true" aria-label="Two-Factor Authentication">
    <div class="modal-header"><h2>Two-Factor Authentication</h2><button type="button" class="secondary auth-close" onclick="closeTwoFactorLoginModal()">Close</button></div>
    <p class="modal-tip">Enter a 6-digit authenticator code or a recovery code to finish signing in.</p>
    <form class="modal-grid auth-form" onsubmit="submitLoginTwoFactor(event)">
      <label class="modal-field">
        <span>Authenticator Or Recovery Code</span>
        <div class="profile-key-wrap two-factor-inline-wrap">
          <input class="menu-search profile-key-input two-factor-inline-input" id="auth-login-2fa-code" type="password" autocomplete="one-time-code">
          <button type="button" class="secondary recovery-codes-visibility profile-key-toggle" id="auth-login-2fa-toggle" onclick="toggleTwoFactorLoginCodeVisibility()" aria-label="Show authenticator code" title="Show authenticator code"><span class="recovery-codes-eye" aria-hidden="true">👁</span></button>
        </div>
      </label>
      <div class="modal-actions two-factor-login-actions">
        <span class="auth-form-error" id="auth-login-2fa-error"></span>
        <button type="submit" class="secondary">Verify</button>
      </div>
    </form>
  </div>
</div>

<div class="modal-backdrop auth-modal-backdrop" id="two-factor-setup-modal" hidden>
  <div class="modal-card auth-card recovery-codes-card two-factor-setup-card" role="dialog" aria-modal="true" aria-label="Set Up Two-Factor Authentication">
    <div class="modal-header"><h2>Set Up 2FA</h2><button type="button" class="secondary auth-close" onclick="closeTwoFactorSetupModal()">Close</button></div>
    <p class="modal-tip" id="two-factor-setup-tip">Use an authenticator app to scan the QR code, then confirm setup with your password and a 6-digit code.</p>
    <div class="two-factor-step">
      <div class="profile-security-heading">Step 1: Scan QR Code</div>
      <div class="two-factor-qr-frame" id="two-factor-qr-frame">
        <div class="two-factor-qr-svg is-empty" id="two-factor-qr-svg"></div>
        <div class="two-factor-qr-actions">
          <button type="button" class="secondary" id="two-factor-generate-button" onclick="startTwoFactorSetup()">Generate</button>
        </div>
      </div>
      <label class="modal-field">
        <span>Secret</span>
        <div class="profile-key-wrap two-factor-secret-wrap">
          <input class="menu-search profile-key-input" id="two-factor-manual-secret" type="password" readonly data-secret="">
          <button type="button" class="symbol-picker-copy profile-key-copy" id="two-factor-secret-copy" onclick="copyTwoFactorSetupSecret()" disabled>Copy</button>
          <button type="button" class="secondary recovery-codes-visibility profile-key-toggle" id="two-factor-secret-toggle" onclick="toggleTwoFactorSetupSecretVisibility()" disabled aria-label="Show secret" title="Show secret"><span class="recovery-codes-eye" aria-hidden="true">👁</span></button>
        </div>
      </label>
    </div>
    <div class="two-factor-step" id="two-factor-setup-password-step">
      <div class="profile-security-heading" id="two-factor-password-step-heading">Step 2: Confirm With Password</div>
      <label class="modal-field" id="two-factor-setup-password-field">
        <span>Current Password</span>
        <div class="profile-key-wrap two-factor-inline-wrap">
          <input class="menu-search profile-key-input two-factor-inline-input" id="two-factor-setup-password" type="password" autocomplete="current-password">
          <button type="button" class="secondary recovery-codes-visibility profile-key-toggle" id="two-factor-password-toggle" onclick="toggleTwoFactorSetupPasswordVisibility()" aria-label="Show current password" title="Show current password"><span class="recovery-codes-eye" aria-hidden="true">👁</span></button>
        </div>
      </label>
    </div>
    <div class="two-factor-step">
      <div class="profile-security-heading">Step 3: Enter Authenticator Code</div>
      <label class="modal-field">
        <span>Authenticator Code</span>
        <div class="profile-key-wrap two-factor-inline-wrap">
          <input class="menu-search profile-key-input two-factor-inline-input" id="two-factor-setup-code" type="password" autocomplete="one-time-code">
          <button type="button" class="secondary recovery-codes-visibility profile-key-toggle" id="two-factor-code-toggle" onclick="toggleTwoFactorSetupCodeVisibility()" aria-label="Show authenticator code" title="Show authenticator code"><span class="recovery-codes-eye" aria-hidden="true">👁</span></button>
        </div>
      </label>
    </div>
    <span class="auth-form-error" id="two-factor-setup-error"></span>
    <div class="modal-actions two-factor-setup-actions">
      <button type="button" class="secondary" onclick="closeTwoFactorSetupModal()">Cancel</button>
      <button type="button" class="secondary" id="two-factor-enable-button" onclick="confirmTwoFactorSetup()" disabled>Enable 2FA</button>
    </div>
  </div>
</div>

<div class="modal-backdrop auth-modal-backdrop" id="two-factor-disable-modal" hidden>
  <div class="modal-card auth-card recovery-codes-card two-factor-disable-card" role="dialog" aria-modal="true" aria-label="Disable Two-Factor Authentication">
    <div class="modal-header"><h2 id="two-factor-disable-title">Disable 2FA</h2><button type="button" class="secondary auth-close" onclick="closeTwoFactorDisableModal()">Close</button></div>
    <p class="modal-tip" id="two-factor-disable-tip">Confirm your password and enter an authenticator or recovery code to disable two-factor authentication.</p>
    <label class="modal-field"><span>Current Password</span><input class="menu-search" id="two-factor-disable-password" type="password" autocomplete="current-password"></label>
    <label class="modal-field"><span>Authenticator Or Recovery Code</span><input class="menu-search" id="two-factor-disable-code" autocomplete="one-time-code"></label>
    <div class="modal-actions two-factor-disable-actions">
      <span class="auth-form-error" id="two-factor-disable-error"></span>
      <button type="button" class="secondary" id="two-factor-disable-submit" onclick="submitTwoFactorDisable()">Disable 2FA</button>
    </div>
  </div>
</div>
"#,
        bootstrap_hidden = bootstrap_hidden,
        auth_hidden = auth_hidden,
        register_tab = register_tab,
        profile_username = profile_username,
        profile_role = profile_role,
        profile_key = profile_key,
        profile_key_disabled = if profile_key.is_empty() {
            " disabled"
        } else {
            ""
        },
        profile_two_factor_status = profile_two_factor_status,
        profile_two_factor_setup_hidden = if profile_two_factor_enabled {
            " hidden"
        } else {
            ""
        },
        profile_two_factor_disable_hidden =
            if profile_two_factor_enabled || profile_two_factor_required {
                ""
            } else {
                " hidden"
            },
        user_role_select_html = user_role_select_html,
        profile_avatar = profile_avatar
    )
}

fn render_upload_modal(data: &PageData) -> String {
    UploadModalTemplate {
        format_select_html: render_single_select_dropdown(
            "upload-format",
            "Format",
            &data.upload_format_options,
            "Auto",
            true,
        ),
        has_corpus_picker: true,
        architecture_select_html: render_single_select_dropdown(
            "upload-architecture",
            "Architecture",
            &data.upload_architecture_options,
            "Auto",
            true,
        ),
        corpus_picker_html: Some(render_upload_corpus_picker(
            &data.upload_corpus_options,
            &data.upload_selected_corpora,
            &data.upload_default_corpus,
            data.upload_corpora_locked,
        )),
        tag_picker_html: render_upload_tag_picker(
            &data.upload_tag_options,
            &data.upload_selected_tags,
        ),
    }
    .render()
    .unwrap_or_else(|_| String::new())
}

fn render_single_select_dropdown(
    name: &str,
    label: &str,
    options: &[String],
    selected: &str,
    search_enabled: bool,
) -> String {
    SingleSelectTemplate {
        name,
        label,
        selected,
        options,
        search_enabled,
    }
    .render()
    .unwrap_or_else(|_| String::new())
}

fn render_upload_corpus_picker(
    options: &[String],
    selected: &[String],
    default_corpus: &str,
    locked: bool,
) -> String {
    UploadCorpusPickerTemplate {
        options_json: serde_json::to_string(options).unwrap_or_else(|_| "[]".to_string()),
        selected_json: serde_json::to_string(selected).unwrap_or_else(|_| "[]".to_string()),
        default_corpus: default_corpus.to_string(),
        locked,
    }
    .render()
    .unwrap_or_else(|_| String::new())
}

fn render_upload_tag_picker(options: &[String], selected: &[String]) -> String {
    UploadTagPickerTemplate {
        options_json: serde_json::to_string(options).unwrap_or_else(|_| "[]".to_string()),
        selected_json: serde_json::to_string(selected).unwrap_or_else(|_| "[]".to_string()),
    }
    .render()
    .unwrap_or_else(|_| String::new())
}

fn status_badge(label: &str, value: &str, healthy: bool) -> String {
    StatusBadgeTemplate {
        label,
        value,
        healthy,
    }
    .render()
    .unwrap_or_else(|_| String::new())
}

pub(crate) fn display_architecture(value: &str) -> String {
    value.to_ascii_uppercase()
}
