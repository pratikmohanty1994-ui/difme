//! On-device fraud scoring. README row 5.1 lists ONNX, but ml/ has no exported model yet (ml/fraud/train.py trains
//! one; nothing writes an .onnx file), so no ONNX runtime is linked. `FraudModel` is the seam: an ONNX-backed
//! implementation (e.g. the `ort` or `tract-onnx` crate loading a Blake3-pinned model) slots in here, and the score
//! already travels to the hub as `edge_fraud_score`, which the verifier compares with its 0.8 fallback threshold.

/// What the device knows about a payment when it scores it.
#[derive(Clone, Debug)]
pub struct Features {
    pub amount_minor: i64,
    pub offline_spent: i64,
    pub created_ms: i64,
}

pub trait FraudModel: Send + Sync {
    /// Probability-like score in [0, 1]; higher is riskier.
    fn score(&self, features: &Features) -> f32;
    fn name(&self) -> &str;
}

/// No model on the device: scores 0 and leaves the decision to the server-side check.
pub struct NoModel;

impl FraudModel for NoModel {
    fn score(&self, _features: &Features) -> f32 {
        0.0
    }

    fn name(&self) -> &str {
        "none (no ONNX model in ml/ yet)"
    }
}
