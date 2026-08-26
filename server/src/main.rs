mod database;
mod endpoints;
mod lockbox_client;
mod server;
mod server_config;

#[macro_use]
extern crate rocket;

use endpoints::utils;
use rocket::fairing::{Fairing, Info};
use rocket::http::Header;
use rocket::{
    serde::json::{json, Value},
    Request, Response,
};
use server::StateChainEntity;

use log::error;

#[catch(500)]
fn internal_error(req: &Request) -> Value {
    let message = format!("500 - Internal Server Error: {}", req.uri());
    error!("{}", message);
    json!(message)
}

#[catch(400)]
fn bad_request(req: &Request) -> Value {
    let message = format!("400 - Bad request: {}", req.uri());
    error!("{}", message);
    json!(message)
}

#[catch(404)]
fn not_found(req: &Request) -> Value {
    let message = format!("404 - Not Found: {}", req.uri());
    error!("{}", message);
    json!(message)
}

#[rocket::main]
async fn main() {
    env_logger::init();

    let config = server_config::ServerConfig::load();

    let statechain_entity = StateChainEntity::new(config)
        .await
        .expect("failed to initialize Mercury dependencies");

    sqlx::migrate!("./migrations")
        .run(&statechain_entity.pool)
        .await
        .unwrap();

    let _ = rocket::build()
        .mount(
            "/",
            routes![
                endpoints::deposit::post_deposit,
                endpoints::deposit::get_token,
                endpoints::bip448_sign::bip448_sign_first,
                endpoints::bip448_sign::bip448_sign_second,
                endpoints::bip448_sign::bip448_signature_count,
                endpoints::lightning_latch::get_paymenthash,
                endpoints::lightning_latch::post_paymenthash,
                endpoints::lightning_latch::transfer_preimage,
                endpoints::transfer_sender::transfer_sender,
                endpoints::transfer_sender::transfer_update_msg,
                endpoints::transfer_receiver::get_msg_addr,
                endpoints::transfer_receiver::statechain_info,
                endpoints::transfer_receiver::transfer_unlock,
                endpoints::transfer_receiver::transfer_receiver,
                endpoints::withdraw::withdraw_complete,
                endpoints::health::ready,
                utils::info_config,
                all_options,
            ],
        )
        .register("/", catchers![not_found, internal_error, bad_request,])
        .manage(statechain_entity)
        .attach(Cors)
        // .attach(MercuryPgDatabase::fairing())
        .launch()
        .await;
}

/// Catches all OPTION requests in order to get the CORS related Fairing triggered.
#[options("/<_..>")]
fn all_options() {
    /* Intentionally left empty */
}

pub struct Cors;

#[rocket::async_trait]
impl Fairing for Cors {
    fn info(&self) -> Info {
        Info {
            name: "Cross-Origin-Resource-Sharing Fairing",
            kind: rocket::fairing::Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, PATCH, PUT, DELETE, HEAD, OPTIONS, GET",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}
