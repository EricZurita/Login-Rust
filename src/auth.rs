use axum::{
    body::Body,
    extract::{Json, Request, State}, // Agregamos State aquí
    http::{self, Response, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{FromRow, PgPool}; // Importante para la BD

// Corregí el typo de "Cliams" a "Claims" :)
#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub exp: usize,
    pub iat: usize,
    pub email: String,
}

pub struct AuthError {
    message: String,
    status_code: StatusCode,
}

#[derive(Deserialize)]
pub struct SignUpData {
    pub email: String,
    pub password: String,
    pub first_name: String,
    pub last_name: String,
}

// Struct para recibir datos del Login
#[derive(Deserialize)]
pub struct SignInData {
    pub email: String,
    pub password: String,
}

// Struct del Usuario (conectado a la BD con FromRow)
#[derive(Clone, Serialize, Deserialize, FromRow)]
pub struct CurrentUser {
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub password_hash: String,
}

// --- Funciones Auxiliares ---

pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    let hash = hash(password, DEFAULT_COST)?;
    Ok(hash)
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response<Body> {
        let body = Json(json!({
            "error": self.message,
        }));

        (self.status_code, body).into_response()
    }
}

pub fn encode_jwt(email: String) -> Result<String, StatusCode> {
    let jwt_token: String = "randomstring".to_string(); // Ojo: Esto debería ir en variables de entorno

    let now = Utc::now();
    let expire: chrono::TimeDelta = Duration::hours(24);
    let exp: usize = (now + expire).timestamp() as usize;
    let iat: usize = now.timestamp() as usize;

    let claim = Claims { iat, exp, email };
    let secret = jwt_token.clone();

    encode(
        &Header::default(),
        &claim,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub fn decode_jwt(jwt: String) -> Result<TokenData<Claims>, StatusCode> {
    let secret = "randomstring".to_string();

    let result: Result<TokenData<Claims>, StatusCode> = decode(
        &jwt,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
    result
}

pub async fn authorize(
    State(pool): State<PgPool>, // Inyectamos la conexión
    mut req: Request,
    next: Next,
) -> Result<Response<Body>, AuthError> {
    let auth_header = req.headers().get(http::header::AUTHORIZATION);

    let auth_header = match auth_header {
        Some(header) => header.to_str().map_err(|_| AuthError {
            message: "Empty header is not allowed".to_string(),
            status_code: StatusCode::FORBIDDEN,
        })?,
        None => {
            return Err(AuthError {
                message: "Please add the JWT token to the header".to_string(),
                status_code: StatusCode::FORBIDDEN,
            })
        }
    };

    let mut header = auth_header.split_whitespace();
    let (_bearer, token) = (header.next(), header.next());

    let token_data = match decode_jwt(token.unwrap_or("").to_string()) {
        Ok(data) => data,
        Err(_) => {
            return Err(AuthError {
                message: "Unable to decode token".to_string(),
                status_code: StatusCode::UNAUTHORIZED,
            })
        }
    };

    let current_user = sqlx::query_as::<_, CurrentUser>(
        "SELECT email, first_name, last_name, password_hash FROM users WHERE email = $1",
    )
    .bind(&token_data.claims.email)
    .fetch_optional(&pool)
    .await
    .map_err(|_| AuthError {
        message: "Database error".to_string(),
        status_code: StatusCode::INTERNAL_SERVER_ERROR,
    })?;

    match current_user {
        Some(user) => {
            req.extensions_mut().insert(user);
            Ok(next.run(req).await)
        }
        None => Err(AuthError {
            message: "You are not an authorized user".to_string(),
            status_code: StatusCode::UNAUTHORIZED,
        }),
    }
}

// Login
pub async fn sign_in(
    State(pool): State<PgPool>, // Inyectamos la conexión
    Json(user_data): Json<SignInData>,
) -> Result<Json<String>, StatusCode> {
    // 1. Poner el email en lowercase
    let email_clean = user_data.email.to_lowercase().trim().to_string();

    // 2. Recuperar usuario de la BD
    let user = sqlx::query_as::<_, CurrentUser>(
        "SELECT email, first_name, last_name, password_hash FROM users WHERE email = $1",
    )
    .bind(&email_clean)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user = match user {
        Some(u) => u,
        None => return Err(StatusCode::UNAUTHORIZED), // Usuario no encontrado
    };

    // 3. Verificar password
    if !verify_password(&user_data.password, &user.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        return Err(StatusCode::UNAUTHORIZED); // Password incorrecto
    }

    // 4. Generar Token
    let token = encode_jwt(user.email).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 5. Retornar Token
    Ok(Json(token))
}

pub async fn sign_up(
    State(pool): State<PgPool>,
    Json(payload): Json<SignUpData>,
) -> Result<(StatusCode, Json<serde_json::Value>), AuthError> {
    
    // 1. Poner el email en lowercase
    let email_clean = payload.email.to_lowercase().trim().to_string();

    // 2. Hashear la contraseña
    let hashed_password = hash_password(&payload.password).map_err(|_| AuthError {
        message: "Error hashing password".to_string(),
        status_code: StatusCode::INTERNAL_SERVER_ERROR                                                                                                                                                                                                                                                                                      ,
    })?;                                                                                                                                    

    // 3. Insertar en la Base de Datos
    let result = sqlx::query(
        "INSERT INTO users (email, first_name, last_name, password_hash) VALUES ($1, $2, $3, $4)"
    )
    .bind(&email_clean)
    .bind(&payload.first_name)
    .bind(&payload.last_name)
    .bind(hashed_password)
    .execute(&pool)
    .await;

    // 4. Manejar el resultado (especialmente si el email ya existe)
    match result {
        Ok(_) => Ok((
            StatusCode::CREATED,
            Json(json!({"message": "User created successfully"}))
        )),
        Err(sqlx::Error::Database(db_err)) => {
            // El código 23505 en Postgres es "Unique Violation" (Email duplicado)
            if db_err.code().unwrap_or_default() == "23505" {
                Err(AuthError {
                    message: "Email already exists".to_string(),
                    status_code: StatusCode::CONFLICT,
                })
            } else {
                Err(AuthError {
                    message: "Database error".to_string(),
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                })
            }
        }
        Err(_) => Err(AuthError {
            message: "Internal server error".to_string(),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
        }),
    }
}