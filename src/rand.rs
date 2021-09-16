use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct RandomValueResponse {
    #[serde(rename = "Data")]
    data: String,
    #[serde(rename = "Time")]
    time: String,
    #[serde(rename = "Status")]
    status: u32,
}

pub async fn generate_state_param() -> String {
    let state: RandomValueResponse = reqwest::get("https://csprng.xyz/v1/api")
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    state.data
}
