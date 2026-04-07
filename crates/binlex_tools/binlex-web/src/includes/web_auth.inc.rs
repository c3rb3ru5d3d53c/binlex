const SESSION_COOKIE_NAME: &str = "binlex_session";
const CAPTCHA_TTL_SECONDS: u64 = 180;
const CAPTCHA_LENGTH: usize = 6;
const LOGIN_CHALLENGE_TTL_SECONDS: u64 = 300;
const TOTP_DIGITS: u32 = 6;
const TOTP_PERIOD_SECONDS: u64 = 30;
const TOTP_WINDOW_STEPS: i64 = 1;

fn captcha_alphabet() -> &'static [u8] {
    b"23456789ABCDEF"
}

fn captcha_glyph(ch: char) -> Option<[u8; 7]> {
    match ch.to_ascii_uppercase() {
        '2' => Some([
            0b11111, 0b00001, 0b00001, 0b11111, 0b10000, 0b10000, 0b11111,
        ]),
        '3' => Some([
            0b11111, 0b00001, 0b00001, 0b01111, 0b00001, 0b00001, 0b11111,
        ]),
        '4' => Some([
            0b10001, 0b10001, 0b10001, 0b11111, 0b00001, 0b00001, 0b00001,
        ]),
        '5' => Some([
            0b11111, 0b10000, 0b10000, 0b11111, 0b00001, 0b00001, 0b11111,
        ]),
        '6' => Some([
            0b11111, 0b10000, 0b10000, 0b11111, 0b10001, 0b10001, 0b11111,
        ]),
        '7' => Some([
            0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000,
        ]),
        '8' => Some([
            0b11111, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b11111,
        ]),
        '9' => Some([
            0b11111, 0b10001, 0b10001, 0b11111, 0b00001, 0b00001, 0b11111,
        ]),
        'A' => Some([
            0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001,
        ]),
        'B' => Some([
            0b11110, 0b10001, 0b10001, 0b11110, 0b10001, 0b10001, 0b11110,
        ]),
        'C' => Some([
            0b01111, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b01111,
        ]),
        'D' => Some([
            0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110,
        ]),
        'E' => Some([
            0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111,
        ]),
        'F' => Some([
            0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000,
        ]),
        _ => None,
    }
}

fn captcha_text() -> String {
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    let alphabet = captcha_alphabet();
    (0..CAPTCHA_LENGTH)
        .filter_map(|_| alphabet.choose(&mut rng).copied().map(char::from))
        .collect()
}

fn render_captcha_png(text: &str) -> Result<Vec<u8>, AppError> {
    use image::{ColorType, ImageEncoder, Rgba, RgbaImage, codecs::png::PngEncoder};
    use rand::Rng;
    let width = 180u32;
    let height = 64u32;
    let mut image = RgbaImage::from_pixel(width, height, Rgba([16, 22, 30, 255]));
    let mut rng = rand::thread_rng();
    for _ in 0..120 {
        let x = rng.gen_range(0..width);
        let y = rng.gen_range(0..height);
        let value = rng.gen_range(26..56) as u8;
        image.put_pixel(x, y, Rgba([value, value + 8, value + 12, 255]));
    }
    for _ in 0..6 {
        let y = rng.gen_range(8..(height - 8));
        let slope = rng.gen_range(-1.4f32..1.4f32);
        let shade = rng.gen_range(55..90) as u8;
        for x in 0..width {
            let sample_y =
                (y as f32 + (x as f32 - width as f32 / 2.0) * slope / 18.0).round() as i32;
            if sample_y >= 0 && sample_y < height as i32 {
                image.put_pixel(
                    x,
                    sample_y as u32,
                    Rgba([shade, shade + 10, shade + 18, 255]),
                );
            }
        }
    }
    let scale = 4i32;
    let start_x = 18i32;
    let start_y = 16i32;
    for (index, ch) in text.chars().enumerate() {
        let glyph = captcha_glyph(ch).ok_or_else(|| AppError::new("unsupported captcha glyph"))?;
        let offset_x = start_x + index as i32 * 24 + rng.gen_range(-1..=1);
        let offset_y = start_y + rng.gen_range(-2..=2);
        let ink = [
            rng.gen_range(220..246) as u8,
            rng.gen_range(224..250) as u8,
            rng.gen_range(228..255) as u8,
            255u8,
        ];
        for (row_idx, row_bits) in glyph.into_iter().enumerate() {
            for col_idx in 0..5 {
                if row_bits & (1 << (4 - col_idx)) == 0 {
                    continue;
                }
                for dy in 0..scale {
                    for dx in 0..scale {
                        let px = offset_x + col_idx * scale + dx;
                        let py = offset_y + row_idx as i32 * scale + dy;
                        if px >= 0 && py >= 0 && px < width as i32 && py < height as i32 {
                            image.put_pixel(px as u32, py as u32, Rgba(ink));
                        }
                    }
                }
            }
        }
    }
    let mut bytes = Vec::new();
    PngEncoder::new(&mut bytes)
        .write_image(image.as_raw(), width, height, ColorType::Rgba8.into())
        .map_err(|error| AppError::new(error.to_string()))?;
    Ok(bytes)
}

#[derive(Clone, Default)]
struct RequestAuthContext {
    user: Option<binlex::databases::UserRecord>,
    session: Option<String>,
}

fn bearer_api_key(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let token = value.strip_prefix("Bearer ")?.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

fn session_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie
        .split(';')
        .map(str::trim)
        .find_map(|pair| pair.strip_prefix(&format!("{}=", SESSION_COOKIE_NAME)))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn temporary_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("Token")?.to_str().ok()?.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.to_string())
}

fn session_cookie_header(value: &str, ttl_seconds: u64) -> Result<HeaderValue, AppError> {
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={ttl}",
        name = SESSION_COOKIE_NAME,
        value = value,
        ttl = ttl_seconds
    ))
    .map_err(|error| AppError::new(error.to_string()))
}

fn clear_session_cookie_header() -> HeaderValue {
    HeaderValue::from_static("binlex_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
}

fn current_user_for_headers(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<binlex::databases::UserRecord>, AppError> {
    if let Some(session) = session_cookie(headers) {
        if let Some(user) = state
            .database
            .session_user(&session)
            .map_err(|error| AppError::unauthorized(error.to_string()))?
        {
            return Ok(Some(user));
        }
    }
    let Some(api_key) = bearer_api_key(headers) else {
        return Ok(None);
    };
    state
        .database
        .auth_user(&api_key)
        .map_err(|error| AppError::unauthorized(error.to_string()))
}

fn staging_key_for_request(
    state: &AppState,
    path: &str,
    headers: &HeaderMap,
) -> Result<String, AppError> {
    if state.route_token_enabled(path) {
        return temporary_token(headers)
            .ok_or_else(|| AppError::unauthorized("missing or invalid temporary token"));
    }
    Ok(temporary_token(headers).unwrap_or_else(|| "__default__".to_string()))
}

fn username_for_request(state: &AppState, headers: &HeaderMap) -> Result<String, AppError> {
    Ok(current_user_for_headers(state, headers)?
        .map(|user| user.username)
        .unwrap_or_default())
}

fn auth_session_response(
    state: &AppState,
    user: Option<binlex::databases::UserRecord>,
) -> AuthSessionResponse {
    AuthSessionResponse {
        authenticated: user.is_some(),
        registration_enabled: state.ui.auth.registration.enabled,
        bootstrap_required: state.database.user_count().unwrap_or(0) == 0,
        user: user.map(user_response),
        two_factor_required: false,
        two_factor_setup_required: false,
        challenge_token: None,
        recovery_codes: None,
    }
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let path = request.uri().path().to_string();
    let context = RequestAuthContext {
        user: current_user_for_headers(state.as_ref(), request.headers())?,
        session: session_cookie(request.headers()),
    };
    if state.route_auth_enabled(&path) {
        let Some(user) = context.user.as_ref() else {
            return Err(AppError::unauthorized(
                "authentication is required for this endpoint",
            ));
        };
        let allowed_roles = state.route_auth_roles(&path);
        if !allowed_roles.is_empty() && !allowed_roles.iter().any(|role| role == &user.role) {
            return Err(AppError::forbidden("role is not allowed for this endpoint"));
        }
    }
    if state.route_token_enabled(&path) {
        let token = temporary_token(request.headers())
            .ok_or_else(|| AppError::unauthorized("missing or invalid temporary token"))?;
        let authorized = state
            .database
            .token_check(&token)
            .map_err(|error| AppError::unauthorized(error.to_string()))?;
        if !authorized {
            return Err(AppError::unauthorized("invalid or expired temporary token"));
        }
    }
    request.extensions_mut().insert(context);
    Ok(next.run(request).await)
}

#[utoipa::path(
    get,
    path = "/api/v1/version",
    tag = "System",
    responses((status = 200, description = "Current binlex version.", body = VersionResponse))
)]
async fn version_api() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: binlex::VERSION.to_string(),
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/token",
    tag = "Tokens",
    request_body = TokenCreateRequest,
    responses((status = 200, description = "Created a temporary token.", body = TokenCreateResponse))
)]
async fn create_token_api(
    State(state): State<Arc<AppState>>,
    Json(_request): Json<TokenCreateRequest>,
) -> Result<Json<TokenCreateResponse>, AppError> {
    let database = state.database.clone();
    let ttl_seconds = state.ui.token.ttl_seconds;
    let response = task::spawn_blocking(move || {
        let (record, plaintext) = database
            .token_create(ttl_seconds)
            .map_err(|error| AppError::new(error.to_string()))?;
        Ok::<TokenCreateResponse, AppError>(TokenCreateResponse {
            token: plaintext,
            expires: record.expires,
        })
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/token/clear",
    tag = "Tokens",
    request_body = TokenClearRequest,
    responses((status = 200, description = "Cleared a temporary token.", body = TokenActionResponse))
)]
async fn clear_token_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<TokenClearRequest>,
) -> Result<Json<TokenActionResponse>, AppError> {
    let database = state.database.clone();
    task::spawn_blocking(move || {
        let disabled = database
            .token_disable_value(&request.token)
            .map_err(|error| AppError::new(error.to_string()))?;
        if !disabled {
            return Err(AppError::new("temporary token not found"));
        }
        Ok::<(), AppError>(())
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(TokenActionResponse { ok: true }))
}

fn user_response(user: binlex::databases::UserRecord) -> AuthUserResponse {
    let timestamp = user.timestamp.clone();
    AuthUserResponse {
        profile_picture: avatar_url_for_user(
            &user.username,
            user.profile_picture.as_deref(),
            Some(&timestamp),
        ),
        username: user.username,
        key: user.api_key,
        role: user.role,
        enabled: user.enabled,
        two_factor_enabled: user.two_factor_enabled,
        two_factor_required: user.two_factor_required,
        timestamp,
    }
}

const PROFILE_PICTURE_MAX_BYTES: usize = 1024 * 1024;
const PROFILE_PICTURE_SIZE: u32 = 128;

fn avatars_dir() -> Result<PathBuf, AppError> {
    let root = dirs::data_local_dir()
        .or_else(dirs::data_dir)
        .unwrap_or_else(std::env::temp_dir)
        .join("binlex")
        .join("avatars");
    fs::create_dir_all(&root).map_err(|error| AppError::new(error.to_string()))?;
    Ok(root)
}

fn avatar_filename(username: &str) -> Result<String, AppError> {
    let normalized = username.trim().to_ascii_lowercase();
    if normalized.is_empty()
        || !normalized
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
    {
        return Err(AppError::new("invalid username"));
    }
    Ok(format!("{}.png", normalized))
}

fn avatar_path_for_username(username: &str) -> Result<PathBuf, AppError> {
    Ok(avatars_dir()?.join(avatar_filename(username)?))
}

fn avatar_url_for_user(
    username: &str,
    stored: Option<&str>,
    _timestamp: Option<&str>,
) -> Option<String> {
    let stored = stored.map(str::trim).unwrap_or_default();
    if stored.is_empty() {
        return None;
    }
    let username = username.trim();
    if username.is_empty() {
        return None;
    }
    Some(format!("/api/v1/profile/picture/{}", username))
}

fn store_profile_picture(username: &str, bytes: &[u8]) -> Result<String, AppError> {
    if bytes.is_empty() {
        return Err(AppError::new("profile picture must not be empty"));
    }
    if bytes.len() > PROFILE_PICTURE_MAX_BYTES {
        return Err(AppError::new("profile picture exceeds 1MB"));
    }
    let image = image::load_from_memory(bytes)
        .map_err(|_| AppError::new("profile picture must be PNG, JPEG, or WebP"))?;
    let rgba = image.to_rgba8();
    let width = rgba.width();
    let height = rgba.height();
    if width == 0 || height == 0 {
        return Err(AppError::new("profile picture could not be decoded"));
    }
    let side = width.min(height);
    let offset_x = (width - side) / 2;
    let offset_y = (height - side) / 2;
    let cropped = image::imageops::crop_imm(&rgba, offset_x, offset_y, side, side).to_image();
    let resized = image::imageops::resize(
        &cropped,
        PROFILE_PICTURE_SIZE,
        PROFILE_PICTURE_SIZE,
        image::imageops::FilterType::Triangle,
    );
    let path = avatar_path_for_username(username)?;
    resized
        .save_with_format(&path, image::ImageFormat::Png)
        .map_err(|error| AppError::new(error.to_string()))?;
    Ok(path
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| format!("avatars/{}", value))
        .ok_or_else(|| AppError::new("failed to persist profile picture path"))?)
}

fn remove_profile_picture_file(username: &str) -> Result<(), AppError> {
    let path = avatar_path_for_username(username)?;
    if path.exists() {
        fs::remove_file(&path).map_err(|error| AppError::new(error.to_string()))?;
    }
    Ok(())
}

fn generate_totp_secret() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut bytes);
    data_encoding::BASE32_NOPAD.encode(&bytes)
}

fn decode_totp_secret(secret: &str) -> Result<Vec<u8>, AppError> {
    data_encoding::BASE32_NOPAD
        .decode(secret.trim().as_bytes())
        .map_err(|_| AppError::new("invalid two-factor secret"))
}

fn otpauth_uri(username: &str, secret: &str) -> String {
    let label = format!("Binlex:{}", username.trim());
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        serde_urlencoded::to_string([("label", label.clone())])
            .unwrap_or_else(|_| format!("label={}", label))
            .trim_start_matches("label="),
        secret.trim(),
        serde_urlencoded::to_string([("issuer", "Binlex")])
            .unwrap_or_else(|_| "issuer=Binlex".to_string())
            .trim_start_matches("issuer="),
        TOTP_DIGITS,
        TOTP_PERIOD_SECONDS
    )
}

fn render_totp_qr_svg(uri: &str) -> Result<String, AppError> {
    use qrcode::{QrCode, render::svg};
    let code = QrCode::new(uri.as_bytes()).map_err(|error| AppError::new(error.to_string()))?;
    Ok(code
        .render::<svg::Color<'_>>()
        .min_dimensions(192, 192)
        .dark_color(svg::Color("#dfe8f3"))
        .light_color(svg::Color("#131a22"))
        .build())
}

fn hotp(secret: &[u8], counter: u64, digits: u32) -> Result<u32, AppError> {
    use hmac::{Hmac, Mac};
    type HmacSha1 = Hmac<sha1::Sha1>;
    let mut mac =
        HmacSha1::new_from_slice(secret).map_err(|error| AppError::new(error.to_string()))?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    Ok(binary % 10u32.pow(digits))
}

fn verify_totp_code(secret: &str, code: &str) -> Result<bool, AppError> {
    let normalized = code.trim();
    if normalized.len() != TOTP_DIGITS as usize || !normalized.chars().all(|ch| ch.is_ascii_digit())
    {
        return Ok(false);
    }
    let secret = decode_totp_secret(secret)?;
    let target = normalized
        .parse::<u32>()
        .map_err(|error| AppError::new(error.to_string()))?;
    let now = chrono::Utc::now().timestamp();
    let current_counter = (now / TOTP_PERIOD_SECONDS as i64) as u64;
    for delta in -TOTP_WINDOW_STEPS..=TOTP_WINDOW_STEPS {
        let counter = if delta < 0 {
            current_counter.saturating_sub(delta.unsigned_abs())
        } else {
            current_counter.saturating_add(delta as u64)
        };
        if hotp(&secret, counter, TOTP_DIGITS)? == target {
            return Ok(true);
        }
    }
    Ok(false)
}

fn login_challenge_response(
    state: &AppState,
    user: binlex::databases::UserRecord,
    challenge_token: String,
    setup_required: bool,
) -> AuthSessionResponse {
    let mut response = auth_session_response(state, None);
    response.two_factor_required = true;
    response.two_factor_setup_required = setup_required;
    response.challenge_token = Some(challenge_token);
    response.user = Some(user_response(user));
    response
}

fn apply_two_factor_policy(user: &mut binlex::databases::UserRecord, state: &AppState) {
    if state.two_factor_required() {
        user.two_factor_required = true;
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/bootstrap",
    tag = "Auth",
    request_body = AuthBootstrapRequest,
    responses((status = 200, description = "Created the initial admin account.", body = AuthSessionResponse))
)]
async fn auth_bootstrap_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AuthBootstrapRequest>,
) -> Result<impl IntoResponse, AppError> {
    if request.password != request.password_confirm {
        return Err(AppError::new("password confirmation does not match"));
    }
    let database = state.database.clone();
    let ttl_seconds = state.ui.auth.session_ttl_seconds;
    let two_factor_required = state.two_factor_required();
    let response = task::spawn_blocking(move || {
        if database
            .user_count()
            .map_err(|error| AppError::new(error.to_string()))?
            > 0
        {
            return Err(AppError::forbidden("bootstrap is no longer available"));
        }
        let (mut user, _, recovery_codes) = database
            .user_create_account(
                &request.username,
                &request.password,
                "admin",
                false,
                two_factor_required,
                None,
            )
            .map_err(|error| AppError::new(error.to_string()))?;
        if two_factor_required {
            let (_, challenge_token) = database
                .login_challenge_create(&user.username, true, LOGIN_CHALLENGE_TTL_SECONDS)
                .map_err(|error| AppError::new(error.to_string()))?;
            user.two_factor_required = true;
            let mut response =
                login_challenge_response(state.as_ref(), user, challenge_token, true);
            response.recovery_codes = Some(recovery_codes);
            return Ok::<(Option<HeaderValue>, AuthSessionResponse), AppError>((None, response));
        }
        let (_, session) = database
            .session_create(&user.username, ttl_seconds)
            .map_err(|error| AppError::new(error.to_string()))?;
        let mut response = auth_session_response(state.as_ref(), Some(user));
        response.recovery_codes = Some(recovery_codes);
        Ok::<(Option<HeaderValue>, AuthSessionResponse), AppError>((
            Some(session_cookie_header(&session, ttl_seconds)?),
            response,
        ))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    if let Some(cookie) = response.0 {
        Ok(([(header::SET_COOKIE, cookie)], Json(response.1)).into_response())
    } else {
        Ok(Json(response.1).into_response())
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "Auth",
    request_body = AuthLoginRequest,
    responses((status = 200, description = "Authenticated a user.", body = AuthSessionResponse))
)]
async fn auth_login_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AuthLoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    let database = state.database.clone();
    let ttl_seconds = state.ui.auth.session_ttl_seconds;
    let response = task::spawn_blocking(move || {
        let mut user = database
            .user_authenticate(&request.username, &request.password)
            .map_err(|error| AppError::unauthorized(error.to_string()))?
            .ok_or_else(|| AppError::unauthorized("invalid username or password"))?;
        apply_two_factor_policy(&mut user, state.as_ref());
        if user.two_factor_enabled || user.two_factor_required {
            let setup_required = user.two_factor_required && !user.two_factor_enabled;
            let (_, challenge_token) = database
                .login_challenge_create(&user.username, setup_required, LOGIN_CHALLENGE_TTL_SECONDS)
                .map_err(|error| AppError::new(error.to_string()))?;
            return Ok::<(Option<HeaderValue>, AuthSessionResponse), AppError>((
                None,
                login_challenge_response(state.as_ref(), user, challenge_token, setup_required),
            ));
        }
        let (_, session) = database
            .session_create(&user.username, ttl_seconds)
            .map_err(|error| AppError::new(error.to_string()))?;
        Ok::<(Option<HeaderValue>, AuthSessionResponse), AppError>((
            Some(session_cookie_header(&session, ttl_seconds)?),
            auth_session_response(state.as_ref(), Some(user)),
        ))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    if let Some(cookie) = response.0 {
        Ok(([(header::SET_COOKIE, cookie)], Json(response.1)).into_response())
    } else {
        Ok(Json(response.1).into_response())
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/login/2fa",
    tag = "Auth",
    request_body = AuthLoginTwoFactorRequest,
    responses((status = 200, description = "Completed a two-factor login challenge.", body = AuthSessionResponse))
)]
async fn auth_login_two_factor_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AuthLoginTwoFactorRequest>,
) -> Result<impl IntoResponse, AppError> {
    let database = state.database.clone();
    let ttl_seconds = state.ui.auth.session_ttl_seconds;
    let response = task::spawn_blocking(move || {
        let (mut user, _) = database
            .login_challenge_user(&request.challenge_token)
            .map_err(|error| AppError::unauthorized(error.to_string()))?
            .ok_or_else(|| AppError::unauthorized("invalid or expired login challenge"))?;
        apply_two_factor_policy(&mut user, state.as_ref());
        if !user.two_factor_enabled {
            return Err(AppError::unauthorized(
                "two-factor authentication is not enabled",
            ));
        }
        let secret = database
            .user_two_factor_secret(&user.username)
            .map_err(|error| AppError::new(error.to_string()))?
            .ok_or_else(|| AppError::unauthorized("two-factor setup is incomplete"))?;
        let verified = verify_totp_code(&secret, &request.code)?;
        if !verified {
            database
                .user_consume_recovery_code(&user.username, &request.code, None)
                .map_err(|error| AppError::unauthorized(error.to_string()))?;
        }
        database
            .login_challenge_disable_value(&request.challenge_token)
            .map_err(|error| AppError::new(error.to_string()))?;
        let (_, session) = database
            .session_create(&user.username, ttl_seconds)
            .map_err(|error| AppError::new(error.to_string()))?;
        Ok::<(AuthSessionResponse, HeaderValue), AppError>((
            auth_session_response(state.as_ref(), Some(user)),
            session_cookie_header(&session, ttl_seconds)?,
        ))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(([(header::SET_COOKIE, response.1)], Json(response.0)))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/login/2fa/setup",
    tag = "Auth",
    request_body = AuthLoginTwoFactorSetupRequest,
    responses((status = 200, description = "Generated TOTP setup for a pending login.", body = TwoFactorSetupResponse))
)]
async fn auth_login_two_factor_setup_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AuthLoginTwoFactorSetupRequest>,
) -> Result<Json<TwoFactorSetupResponse>, AppError> {
    let database = state.database.clone();
    let response = task::spawn_blocking(move || {
        let (user, challenge) = database
            .login_challenge_user(&request.challenge_token)
            .map_err(|error| AppError::unauthorized(error.to_string()))?
            .ok_or_else(|| AppError::unauthorized("invalid or expired login challenge"))?;
        if !challenge.setup_required {
            return Err(AppError::forbidden("two-factor setup is not required"));
        }
        let secret = generate_totp_secret();
        database
            .user_begin_two_factor_setup(&user.username, &secret)
            .map_err(|error| AppError::new(error.to_string()))?;
        Ok::<TwoFactorSetupResponse, AppError>(TwoFactorSetupResponse {
            manual_secret: secret.clone(),
            qr_svg: render_totp_qr_svg(&otpauth_uri(&user.username, &secret))?,
        })
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/login/2fa/enable",
    tag = "Auth",
    request_body = AuthLoginTwoFactorRequest,
    responses((status = 200, description = "Enabled TOTP during a pending login.", body = AuthSessionResponse))
)]
async fn auth_login_two_factor_enable_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AuthLoginTwoFactorRequest>,
) -> Result<impl IntoResponse, AppError> {
    let database = state.database.clone();
    let ttl_seconds = state.ui.auth.session_ttl_seconds;
    let response = task::spawn_blocking(move || {
        let (user, challenge) = database
            .login_challenge_user(&request.challenge_token)
            .map_err(|error| AppError::unauthorized(error.to_string()))?
            .ok_or_else(|| AppError::unauthorized("invalid or expired login challenge"))?;
        if !challenge.setup_required {
            return Err(AppError::forbidden("two-factor setup is not required"));
        }
        let secret = database
            .user_two_factor_secret(&user.username)
            .map_err(|error| AppError::new(error.to_string()))?
            .ok_or_else(|| AppError::new("two-factor setup has not been started"))?;
        if !verify_totp_code(&secret, &request.code)? {
            return Err(AppError::unauthorized("invalid authenticator code"));
        }
        let mut user = database
            .user_enable_two_factor(&user.username, None)
            .map_err(|error| AppError::new(error.to_string()))?;
        apply_two_factor_policy(&mut user, state.as_ref());
        let recovery_codes = database
            .user_regenerate_recovery_codes(&user.username, None)
            .map_err(|error| AppError::new(error.to_string()))?;
        database
            .login_challenge_disable_value(&request.challenge_token)
            .map_err(|error| AppError::new(error.to_string()))?;
        let (_, session) = database
            .session_create(&user.username, ttl_seconds)
            .map_err(|error| AppError::new(error.to_string()))?;
        let mut response = auth_session_response(state.as_ref(), Some(user));
        response.recovery_codes = Some(recovery_codes);
        Ok::<(AuthSessionResponse, HeaderValue), AppError>((
            response,
            session_cookie_header(&session, ttl_seconds)?,
        ))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(([(header::SET_COOKIE, response.1)], Json(response.0)))
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/captcha",
    tag = "Auth",
    responses((status = 200, description = "Generated a registration captcha.", body = CaptchaResponse))
)]
async fn auth_captcha_api(
    State(state): State<Arc<AppState>>,
) -> Result<Json<CaptchaResponse>, AppError> {
    let database = state.database.clone();
    let response = task::spawn_blocking(move || {
        let _ = database.captcha_clear_expired();
        let text = captcha_text();
        let png = render_captcha_png(&text)?;
        let (record, _) = database
            .captcha_create(&text, CAPTCHA_TTL_SECONDS)
            .map_err(|error| AppError::new(error.to_string()))?;
        Ok::<CaptchaResponse, AppError>(CaptchaResponse {
            captcha_id: record.id,
            image_base64:
                <base64::engine::general_purpose::GeneralPurpose as base64::Engine>::encode(
                    &base64::engine::general_purpose::STANDARD,
                    png,
                ),
            expires: record.expires,
        })
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/register",
    tag = "Auth",
    request_body = AuthRegisterRequest,
    responses((status = 200, description = "Registered a user account.", body = AuthSessionResponse))
)]
async fn auth_register_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AuthRegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    if !state.ui.auth.registration.enabled {
        return Err(AppError::forbidden("registration is disabled"));
    }
    if request.password != request.password_confirm {
        return Err(AppError::new("password confirmation does not match"));
    }
    let database = state.database.clone();
    let ttl_seconds = state.ui.auth.session_ttl_seconds;
    let two_factor_required = state.two_factor_required();
    let response = task::spawn_blocking(move || {
        let _ = database.captcha_clear_expired();
        if database
            .user_count()
            .map_err(|error| AppError::new(error.to_string()))?
            == 0
        {
            return Err(AppError::forbidden(
                "registration is unavailable until the initial admin is created",
            ));
        }
        database
            .captcha_verify_once(&request.captcha_id, &request.captcha_answer)
            .map_err(|error| AppError::new(error.to_string()))?;
        let (mut user, _, recovery_codes) = database
            .user_create_account(
                &request.username,
                &request.password,
                "user",
                false,
                two_factor_required,
                None,
            )
            .map_err(|error| AppError::new(error.to_string()))?;
        if two_factor_required {
            let (_, challenge_token) = database
                .login_challenge_create(&user.username, true, LOGIN_CHALLENGE_TTL_SECONDS)
                .map_err(|error| AppError::new(error.to_string()))?;
            user.two_factor_required = true;
            let mut response =
                login_challenge_response(state.as_ref(), user, challenge_token, true);
            response.recovery_codes = Some(recovery_codes);
            return Ok::<(Option<HeaderValue>, AuthSessionResponse), AppError>((None, response));
        }
        let (_, session) = database
            .session_create(&user.username, ttl_seconds)
            .map_err(|error| AppError::new(error.to_string()))?;
        let mut response = auth_session_response(state.as_ref(), Some(user));
        response.recovery_codes = Some(recovery_codes);
        Ok::<(Option<HeaderValue>, AuthSessionResponse), AppError>((
            Some(session_cookie_header(&session, ttl_seconds)?),
            response,
        ))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    if let Some(cookie) = response.0 {
        Ok(([(header::SET_COOKIE, cookie)], Json(response.1)).into_response())
    } else {
        Ok(Json(response.1).into_response())
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "Auth",
    responses((status = 200, description = "Ended the current session.", body = TokenActionResponse))
)]
async fn auth_logout_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
) -> Result<impl IntoResponse, AppError> {
    if let Some(session) = context.session {
        let database = state.database.clone();
        task::spawn_blocking(move || {
            database
                .session_disable_value(&session)
                .map_err(|error| AppError::new(error.to_string()))
        })
        .await
        .map_err(|error| AppError::new(error.to_string()))??;
    }
    Ok((
        [(header::SET_COOKIE, clear_session_cookie_header())],
        Json(TokenActionResponse { ok: true }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/me",
    tag = "Auth",
    responses((status = 200, description = "Current browser auth state.", body = AuthSessionResponse))
)]
async fn auth_me_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
) -> Json<AuthSessionResponse> {
    Json(auth_session_response(state.as_ref(), context.user))
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/username/check",
    tag = "Auth",
    params(UsernameCheckParams),
    responses((status = 200, description = "Checked username validity and availability.", body = UsernameCheckResponse))
)]
async fn auth_username_check_api(
    State(state): State<Arc<AppState>>,
    Query(params): Query<UsernameCheckParams>,
) -> Json<UsernameCheckResponse> {
    let database = state.database.clone();
    let username = params.username.clone();
    let fallback_username = username.clone();
    let response = task::spawn_blocking(move || match database.username_availability(&username) {
        Ok((normalized, available)) => UsernameCheckResponse {
            normalized,
            valid: true,
            available,
            error: None,
        },
        Err(error) => UsernameCheckResponse {
            normalized: username.trim().to_ascii_lowercase(),
            valid: false,
            available: false,
            error: Some(error.to_string()),
        },
    })
    .await
    .unwrap_or_else(|error| UsernameCheckResponse {
        normalized: fallback_username.trim().to_ascii_lowercase(),
        valid: false,
        available: false,
        error: Some(error.to_string()),
    });
    Json(response)
}

#[utoipa::path(
    get,
    path = "/api/v1/profile",
    tag = "Auth",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "Current profile.", body = AuthUserResponse))
)]
async fn profile_get_api(
    Extension(context): Extension<RequestAuthContext>,
) -> Result<Json<AuthUserResponse>, AppError> {
    let user = context
        .user
        .ok_or_else(|| AppError::unauthorized("authentication is required"))?;
    Ok(Json(user_response(user)))
}

#[utoipa::path(
    post,
    path = "/api/v1/profile/password",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = ProfilePasswordRequest,
    responses((status = 200, description = "Changed the current password.", body = TokenActionResponse))
)]
async fn profile_password_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
    Json(request): Json<ProfilePasswordRequest>,
) -> Result<Json<TokenActionResponse>, AppError> {
    if request.new_password != request.password_confirm {
        return Err(AppError::new("password confirmation does not match"));
    }
    let user = context
        .user
        .ok_or_else(|| AppError::unauthorized("authentication is required"))?;
    let database = state.database.clone();
    task::spawn_blocking(move || {
        database
            .user_change_password(
                &user.username,
                &request.current_password,
                &request.new_password,
            )
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(TokenActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/profile/picture",
    tag = "Auth",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "Updated the profile picture.", body = AuthUserResponse))
)]
async fn profile_picture_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
    mut multipart: Multipart,
) -> Result<Json<AuthUserResponse>, AppError> {
    let user = context
        .user
        .ok_or_else(|| AppError::unauthorized("authentication is required"))?;
    let mut bytes = Vec::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|error| AppError::new(error.to_string()))?
    {
        if field.name() != Some("picture") {
            continue;
        }
        bytes = field
            .bytes()
            .await
            .map_err(|error| AppError::new(error.to_string()))?
            .to_vec();
        break;
    }
    if bytes.is_empty() {
        return Err(AppError::new("profile picture must not be empty"));
    }
    let database = state.database.clone();
    let response = task::spawn_blocking(move || {
        let stored = store_profile_picture(&user.username, &bytes)?;
        database
            .user_update_profile_picture(&user.username, Some(&stored))
            .map(user_response)
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    delete,
    path = "/api/v1/profile/picture",
    tag = "Auth",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "Removed the profile picture.", body = AuthUserResponse))
)]
async fn profile_picture_delete_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
) -> Result<Json<AuthUserResponse>, AppError> {
    let user = context
        .user
        .ok_or_else(|| AppError::unauthorized("authentication is required"))?;
    let database = state.database.clone();
    let response = task::spawn_blocking(move || {
        remove_profile_picture_file(&user.username)?;
        database
            .user_update_profile_picture(&user.username, None)
            .map(user_response)
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/api/v1/profile/picture/{username}",
    tag = "Auth",
    params(ProfilePictureParams),
    responses((status = 200, description = "Profile picture image"))
)]
async fn profile_picture_get_api(
    State(state): State<Arc<AppState>>,
    Path(params): Path<ProfilePictureParams>,
) -> Result<impl IntoResponse, AppError> {
    let database = state.database.clone();
    let username = params.username;
    let bytes = task::spawn_blocking(move || {
        let user = database
            .user_get(&username)
            .map_err(|error| AppError::new(error.to_string()))?
            .ok_or_else(|| AppError::new("user does not exist"))?;
        let stored = user
            .profile_picture
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| AppError::new("profile picture not found"))?;
        let filename = stored
            .rsplit('/')
            .next()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| AppError::new("profile picture not found"))?;
        fs::read(avatars_dir()?.join(filename)).map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok((
        [(header::CONTENT_TYPE, HeaderValue::from_static("image/png"))],
        bytes,
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/profile/key/regenerate",
    tag = "Auth",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "Regenerated the current API key.", body = KeyRegenerateResponse))
)]
async fn profile_key_regenerate_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
) -> Result<Json<KeyRegenerateResponse>, AppError> {
    let user = context
        .user
        .ok_or_else(|| AppError::unauthorized("authentication is required"))?;
    let database = state.database.clone();
    let key = task::spawn_blocking(move || {
        database
            .user_regenerate_key(&user.username, None)
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(KeyRegenerateResponse { key }))
}

#[utoipa::path(
    post,
    path = "/api/v1/profile/recovery/regenerate",
    tag = "Auth",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "Regenerated recovery codes.", body = RecoveryCodesResponse))
)]
async fn profile_recovery_regenerate_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
) -> Result<Json<RecoveryCodesResponse>, AppError> {
    let user = context
        .user
        .ok_or_else(|| AppError::unauthorized("authentication is required"))?;
    let database = state.database.clone();
    let recovery_codes = task::spawn_blocking(move || {
        database
            .user_regenerate_recovery_codes(&user.username, None)
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(RecoveryCodesResponse { recovery_codes }))
}

#[utoipa::path(
    post,
    path = "/api/v1/profile/2fa/setup",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = TwoFactorSetupRequest,
    responses((status = 200, description = "Started TOTP setup for the current user.", body = TwoFactorSetupResponse))
)]
async fn profile_two_factor_setup_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
    Json(_request): Json<TwoFactorSetupRequest>,
) -> Result<Json<TwoFactorSetupResponse>, AppError> {
    let user = context
        .user
        .ok_or_else(|| AppError::unauthorized("authentication is required"))?;
    let database = state.database.clone();
    let response = task::spawn_blocking(move || {
        let secret = generate_totp_secret();
        database
            .user_begin_two_factor_setup(&user.username, &secret)
            .map_err(|error| AppError::new(error.to_string()))?;
        Ok::<TwoFactorSetupResponse, AppError>(TwoFactorSetupResponse {
            manual_secret: secret.clone(),
            qr_svg: render_totp_qr_svg(&otpauth_uri(&user.username, &secret))?,
        })
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/profile/2fa/enable",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = TwoFactorEnableRequest,
    responses((status = 200, description = "Enabled TOTP for the current user.", body = AuthSessionResponse))
)]
async fn profile_two_factor_enable_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
    Json(request): Json<TwoFactorEnableRequest>,
) -> Result<Json<AuthSessionResponse>, AppError> {
    let user = context
        .user
        .ok_or_else(|| AppError::unauthorized("authentication is required"))?;
    let database = state.database.clone();
    let response = task::spawn_blocking(move || {
        let authenticated = database
            .user_authenticate(&user.username, &request.current_password)
            .map_err(|error| AppError::new(error.to_string()))?
            .is_some();
        if !authenticated {
            return Err(AppError::unauthorized("invalid password"));
        }
        let secret = database
            .user_two_factor_secret(&user.username)
            .map_err(|error| AppError::new(error.to_string()))?
            .ok_or_else(|| AppError::new("two-factor setup has not been started"))?;
        if !verify_totp_code(&secret, &request.code)? {
            return Err(AppError::unauthorized("invalid authenticator code"));
        }
        let mut user = database
            .user_enable_two_factor(&user.username, None)
            .map_err(|error| AppError::new(error.to_string()))?;
        apply_two_factor_policy(&mut user, state.as_ref());
        let recovery_codes = database
            .user_regenerate_recovery_codes(&user.username, None)
            .map_err(|error| AppError::new(error.to_string()))?;
        let mut response = auth_session_response(state.as_ref(), Some(user));
        response.recovery_codes = Some(recovery_codes);
        Ok::<AuthSessionResponse, AppError>(response)
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/profile/2fa/disable",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = TwoFactorDisableRequest,
    responses((status = 200, description = "Disabled TOTP for the current user.", body = AuthUserResponse))
)]
async fn profile_two_factor_disable_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
    Json(request): Json<TwoFactorDisableRequest>,
) -> Result<Json<AuthUserResponse>, AppError> {
    let user = context
        .user
        .ok_or_else(|| AppError::unauthorized("authentication is required"))?;
    let database = state.database.clone();
    let clear_required = !state.two_factor_required();
    let response = task::spawn_blocking(move || {
        let authenticated = database
            .user_authenticate(&user.username, &request.current_password)
            .map_err(|error| AppError::new(error.to_string()))?
            .is_some();
        if !authenticated {
            return Err(AppError::unauthorized("invalid password"));
        }
        let secret = database
            .user_two_factor_secret(&user.username)
            .map_err(|error| AppError::new(error.to_string()))?;
        let verified = secret
            .as_deref()
            .map(|value| verify_totp_code(value, &request.code))
            .transpose()?
            .unwrap_or(false);
        if !verified {
            database
                .user_consume_recovery_code(&user.username, &request.code, None)
                .map_err(|error| AppError::unauthorized(error.to_string()))?;
        }
        database
            .user_disable_two_factor(&user.username, clear_required, None)
            .map(user_response)
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/password/reset",
    tag = "Auth",
    request_body = AuthPasswordResetRequest,
    responses((status = 200, description = "Reset a password using a recovery code.", body = TokenActionResponse))
)]
async fn auth_password_reset_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AuthPasswordResetRequest>,
) -> Result<Json<TokenActionResponse>, AppError> {
    if request.new_password != request.password_confirm {
        return Err(AppError::new("password confirmation does not match"));
    }
    let database = state.database.clone();
    task::spawn_blocking(move || {
        let _ = database.captcha_clear_expired();
        database
            .captcha_verify_once(&request.captcha_id, &request.captcha_answer)
            .map_err(|error| AppError::new(error.to_string()))?;
        database
            .user_reset_with_recovery_code(
                &request.username,
                &request.recovery_code,
                &request.new_password,
                None,
            )
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(TokenActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/profile/delete",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = ProfileDeleteRequest,
    responses((status = 200, description = "Deleted the current account.", body = TokenActionResponse))
)]
async fn profile_delete_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
    Json(request): Json<ProfileDeleteRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = context
        .user
        .ok_or_else(|| AppError::unauthorized("authentication is required"))?;
    let session = context.session.clone();
    let database = state.database.clone();
    task::spawn_blocking(move || {
        let authenticated = database
            .user_authenticate(&user.username, &request.password)
            .map_err(|error| AppError::new(error.to_string()))?
            .is_some();
        if !authenticated {
            return Err(AppError::unauthorized("invalid password"));
        }
        database
            .user_delete(&user.username)
            .map_err(|error| AppError::new(error.to_string()))?;
        let _ = remove_profile_picture_file(&user.username);
        if let Some(session) = session {
            let _ = database.session_disable_value(&session);
        }
        Ok::<(), AppError>(())
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok((
        [(header::SET_COOKIE, clear_session_cookie_header())],
        Json(TokenActionResponse { ok: true }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/users",
    tag = "Auth",
    security(("bearer_auth" = [])),
    params(UsersSearchParams),
    responses((status = 200, description = "Listed users.", body = UsersListResponse))
)]
async fn admin_users_api(
    State(state): State<Arc<AppState>>,
    Query(params): Query<UsersSearchParams>,
) -> Result<Json<UsersListResponse>, AppError> {
    let database = state.database.clone();
    let response = task::spawn_blocking(move || {
        let total_results = database
            .user_search_total(&params.q)
            .map_err(|error| AppError::new(error.to_string()))?;
        let page = database
            .user_search(&params.q, params.page.max(1), params.limit.max(1))
            .map_err(|error| AppError::new(error.to_string()))?;
        Ok::<UsersListResponse, AppError>(UsersListResponse {
            items: page.items.into_iter().map(user_response).collect(),
            page: page.page,
            limit: page.page_size,
            total_results,
            has_next: page.has_next,
        })
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/users/create",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = AdminUserCreateRequest,
    responses((status = 200, description = "Created a user.", body = AdminUserCreateResponse))
)]
async fn admin_user_create_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AdminUserCreateRequest>,
) -> Result<Json<AdminUserCreateResponse>, AppError> {
    if request.password != request.password_confirm {
        return Err(AppError::new("password confirmation does not match"));
    }
    let database = state.database.clone();
    let two_factor_required = state.two_factor_required();
    let response = task::spawn_blocking(move || {
        let (user, key, recovery_codes) = database
            .user_create_account(
                &request.username,
                &request.password,
                &request.role,
                false,
                two_factor_required,
                None,
            )
            .map_err(|error| AppError::new(error.to_string()))?;
        Ok::<AdminUserCreateResponse, AppError>(AdminUserCreateResponse {
            user: user_response(user),
            key,
            recovery_codes,
        })
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/users/role",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = AdminUserRoleRequest,
    responses((status = 200, description = "Updated a user role.", body = AuthUserResponse))
)]
async fn admin_user_role_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AdminUserRoleRequest>,
) -> Result<Json<AuthUserResponse>, AppError> {
    let database = state.database.clone();
    let two_factor_required = state.two_factor_required();
    let response = task::spawn_blocking(move || {
        let user = database
            .user_update_role(&request.username, &request.role)
            .map_err(|error| AppError::new(error.to_string()))?;
        if two_factor_required && !user.two_factor_required {
            database
                .user_require_two_factor(&request.username, true, None)
                .map(user_response)
                .map_err(|error| AppError::new(error.to_string()))
        } else {
            Ok(user_response(user))
        }
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/users/enabled",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = AdminUserEnabledRequest,
    responses((status = 200, description = "Enabled or disabled a user account.", body = AuthUserResponse))
)]
async fn admin_user_enabled_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AdminUserEnabledRequest>,
) -> Result<Json<AuthUserResponse>, AppError> {
    let database = state.database.clone();
    let response = task::spawn_blocking(move || {
        if request.enabled {
            database
                .user_enable(&request.username)
                .map_err(|error| AppError::new(error.to_string()))?;
        } else {
            database
                .user_disable(&request.username)
                .map_err(|error| AppError::new(error.to_string()))?;
        }
        database
            .user_get(&request.username)
            .map_err(|error| AppError::new(error.to_string()))?
            .map(user_response)
            .ok_or_else(|| AppError::new("user no longer exists"))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/users/password/reset",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = AdminUserNameRequest,
    responses((status = 200, description = "Reset a user password.", body = AdminPasswordResetResponse))
)]
async fn admin_user_password_reset_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AdminUserNameRequest>,
) -> Result<Json<AdminPasswordResetResponse>, AppError> {
    let database = state.database.clone();
    let response = task::spawn_blocking(move || {
        let password = database
            .user_reset(&request.username, None)
            .map_err(|error| AppError::new(error.to_string()))?;
        Ok::<AdminPasswordResetResponse, AppError>(AdminPasswordResetResponse {
            username: request.username,
            password,
        })
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/users/key/regenerate",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = AdminUserNameRequest,
    responses((status = 200, description = "Regenerated a user API key.", body = KeyRegenerateResponse))
)]
async fn admin_user_key_regenerate_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AdminUserNameRequest>,
) -> Result<Json<KeyRegenerateResponse>, AppError> {
    let database = state.database.clone();
    let key = task::spawn_blocking(move || {
        database
            .user_regenerate_key(&request.username, None)
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(KeyRegenerateResponse { key }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/users/delete",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = AdminUserNameRequest,
    responses((status = 200, description = "Deleted a user account.", body = TokenActionResponse))
)]
async fn admin_user_delete_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AdminUserNameRequest>,
) -> Result<Json<TokenActionResponse>, AppError> {
    let database = state.database.clone();
    task::spawn_blocking(move || {
        let _ = remove_profile_picture_file(&request.username);
        database
            .user_delete(&request.username)
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(TokenActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/users/picture/delete",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = AdminUserNameRequest,
    responses((status = 200, description = "Removed a user's avatar.", body = AuthUserResponse))
)]
async fn admin_user_picture_delete_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AdminUserNameRequest>,
) -> Result<Json<AuthUserResponse>, AppError> {
    let database = state.database.clone();
    let response = task::spawn_blocking(move || {
        remove_profile_picture_file(&request.username)?;
        database
            .user_update_profile_picture(&request.username, None)
            .map(user_response)
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/users/2fa/require",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = AdminUserTwoFactorRequiredRequest,
    responses((status = 200, description = "Updated a user's 2FA requirement.", body = AuthUserResponse))
)]
async fn admin_user_two_factor_require_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AdminUserTwoFactorRequiredRequest>,
) -> Result<Json<AuthUserResponse>, AppError> {
    let database = state.database.clone();
    let response = task::spawn_blocking(move || {
        database
            .user_require_two_factor(&request.username, request.required, None)
            .map(user_response)
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/users/2fa/disable",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = AdminUserNameRequest,
    responses((status = 200, description = "Disabled a user's 2FA.", body = AuthUserResponse))
)]
async fn admin_user_two_factor_disable_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AdminUserNameRequest>,
) -> Result<Json<AuthUserResponse>, AppError> {
    let database = state.database.clone();
    let clear_required = !state.two_factor_required();
    let response = task::spawn_blocking(move || {
        database
            .user_disable_two_factor(&request.username, clear_required, None)
            .map(user_response)
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/users/2fa/reset",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = AdminUserNameRequest,
    responses((status = 200, description = "Reset a user's 2FA and require setup again.", body = AuthUserResponse))
)]
async fn admin_user_two_factor_reset_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AdminUserNameRequest>,
) -> Result<Json<AuthUserResponse>, AppError> {
    let database = state.database.clone();
    let clear_required = !state.two_factor_required();
    let response = task::spawn_blocking(move || {
        database
            .user_disable_two_factor(&request.username, clear_required, None)
            .map(user_response)
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}
