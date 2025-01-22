mod cochilli;
mod utils;

use wasm_bindgen::prelude::*;

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet() {
    alert("Hello, bulletproof-wasm-2!");
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProofData {
    proof: Vec<u8>,
    committed_value: Vec<u8>,
}

#[wasm_bindgen]
pub struct ProofSystem {
    bp_gens: BulletproofGens,
    pc_gens: PedersenGens,
}

#[wasm_bindgen]
impl ProofSystem {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let bp_gens = BulletproofGens::new(64, 1);
        let pc_gens = PedersenGens::default();

        ProofSystem { bp_gens, pc_gens }
    }

    pub fn create_range_proof(&self, value: u64) -> Result<JsValue, JsValue> {
        let mut prover_transcript = Transcript::new(b"range_proof");
        let blinding = Scalar::from(value);
        // let blinding = Scalar::random(&mut thread_rng());

        let (proof, committed_value) = RangeProof::prove_single(
            &self.bp_gens,
            &self.pc_gens,
            &mut prover_transcript,
            value,
            &blinding,
            32,
        )
        .map_err(|e| JsValue::from_str(&format!("Proof generation failed: {}", e)))?;

        let proof_data = ProofData {
            proof: proof.to_bytes().to_vec(),
            committed_value: committed_value.to_bytes().to_vec(),
        };

        serde_wasm_bindgen::to_value(&proof_data)
            .map_err(|e| JsValue::from_str(&format!("Serialization failed: {}", e)))
    }

    pub fn verify_range_proof(&self, proof_data: JsValue) -> Result<bool, JsValue> {
        let proof_data: ProofData = serde_wasm_bindgen::from_value(proof_data)
            .map_err(|e| JsValue::from_str(&format!("Deserialization failed: {}", e)))?;

        let proof = RangeProof::from_bytes(&proof_data.proof)
            .map_err(|e| JsValue::from_str(&format!("Invalid proof bytes: {}", e)))?;

        let committed_value: CompressedRistretto =
            CompressedRistretto::from_slice(&proof_data.committed_value).unwrap();

        let mut verifier_transcript = Transcript::new(b"range_proof");

        // Using verify_proof_single instead of verify_single
        proof
            .verify_single(
                &self.bp_gens,
                &self.pc_gens,
                &mut verifier_transcript,
                &committed_value,
                32,
            )
            .map_err(|e| JsValue::from_str(&format!("Verification failed: {}", e)))?;

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test]
    fn test_range_proof_valid_input() {
        let proof_system = ProofSystem::new();
        let value = 42u64;

        let proof_data = proof_system.create_range_proof(value).unwrap();
        let verification_result = proof_system.verify_range_proof(proof_data).unwrap();
        assert!(verification_result);
    }
}
