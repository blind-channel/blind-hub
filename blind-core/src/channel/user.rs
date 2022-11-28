use bitcoin::{Transaction, Script, Txid, Network, secp256k1::{SecretKey, ecdsa::Signature, Message}, Address, util::sighash::SighashCache, hashes::Hash};
use curv::{elliptic::curves::{secp256_k1::{Secp256k1Scalar, Secp256k1Point, self}, ECScalar, ECPoint, bls12_381::{scalar::FieldScalar, g1::G1Point}}};
use fancy_garbling::{circuit::Circuit, twopac::semihonest::Evaluator};
use ocelot::ot::NaorPinkasReceiver;
use scuttlebutt::{AbstractChannel, AesRng};
use sha2::{Sha256, Digest};

use crate::{transaction::{new_unsigned_transcation_funding, new_unsigned_transcation_commitement, new_unsigned_transaction_split_final, sign_transaction, compose_transaction_split, compose_transaction_multisig, compose_transaction_funding}, script::{new_commitment_script, new_funding_script}, channel::Transferable, ecdsa::AdaptorSignature, zkgc::{prove_all_transactions, prove_split_final_transaction}};

use super::{ChannelParams, ChannelStatus, ChannelSK, ChannelPK, FundingSigner, ChannelUserRole, DeliveryTransactionPack};

#[derive(Clone)]
pub struct ChannelUser{
    pub params: ChannelParams,
    pub status: ChannelStatus,
    pub sk_user: ChannelSK,
    pub pk_user: ChannelPK,
    pub pk_blnd: ChannelPK,
    pub commitment_amount_user_randomness: FieldScalar,
    pub commitment_amount_blnd_randomness: FieldScalar
}

struct BuildCommitmentResult {
    rev_cred_user: SecretKey,
    rev_hash_blnd: [u8;32],
    commitment_script: Script,
    commitment_transaction: Transaction
}

impl ChannelUser {
    fn build_unsigned_funding_transaction<C: AbstractChannel>(
        chan: &mut C,
        funding_template_user: Transaction,
        funding_script: &Script,
        funding_output_amount: u64
    ) -> anyhow::Result<Transaction> {
        funding_template_user.write_channel(chan)?;
        chan.flush()?;
        let funding_template_blnd = Transaction::read_channel(chan)?;
        Ok(new_unsigned_transcation_funding(
            funding_template_user,
            funding_template_blnd,
            funding_output_amount,
            funding_script
        ))
    }

    fn build_unsigned_commitment_transaction<C: AbstractChannel>(
        chan: &mut C,
        funding_txid: &Txid,
        pk_user: &ChannelPK,
        pk_blnd: &ChannelPK,
        commitment_output_amount: u64,
        commitment_timelock_abs_split: u32,
        commitment_timelock_abs_punish: u32,
    ) -> anyhow::Result<BuildCommitmentResult> {
        let rev_cred_user = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let rev_hash_user: [u8;32] = Sha256::digest(&Sha256::digest(&rev_cred_user.as_ref())).try_into()?;
        chan.write_bytes(&rev_hash_user)?;
        chan.flush()?;
        let mut rev_hash_blnd = [0u8;32];
        chan.read_bytes(&mut rev_hash_blnd)?;

        let commitment_script = new_commitment_script(
            commitment_timelock_abs_split,
            commitment_timelock_abs_punish,
            &pk_user.pk_sig,
            &pk_blnd.pk_sig,
            &rev_hash_user,
            &rev_hash_blnd,
            &pk_user.pk_pub,
            &pk_blnd.pk_pub
        );

        let commitment_transaction = new_unsigned_transcation_commitement(
            funding_txid,
            0,
            commitment_output_amount,
            &commitment_script
        );

        Ok(BuildCommitmentResult {
            rev_cred_user,
            rev_hash_blnd,
            commitment_script,
            commitment_transaction
        })
    }

    pub fn new<C: AbstractChannel, S: FundingSigner>(
        chan: &mut C,
        network: Network,
        funding_signer: &S,
        funding_template_user: Transaction,
        funding_output_amount: u64,
        commitment_output_amount: u64,
        split_return_amount: u64,
        commitment_timelock_abs_split: u32,
        commitment_timelock_abs_punish: u32,
        timeout_sequence: u32
    ) -> anyhow::Result<Self> {
        let sk_user = ChannelSK::new();
        let pk_user = ChannelPK::from_sk(&sk_user);
        pk_user.write_channel(chan)?;
        chan.flush()?;
        let pk_blnd = ChannelPK::read_channel(chan)?;

        let funding_script = new_funding_script(
            &pk_user.pk_sig,
            &pk_blnd.pk_sig
        );
        let funding_transaction_unsigned = Self::build_unsigned_funding_transaction(
            chan,
            funding_template_user,
            &funding_script,
            funding_output_amount
        )?;

        let BuildCommitmentResult{
            rev_cred_user,
            rev_hash_blnd,
            commitment_script,
            commitment_transaction
        } = Self::build_unsigned_commitment_transaction(
            chan,
            &funding_transaction_unsigned.txid(),
            &pk_user,
            &pk_blnd,
            commitment_output_amount,
            commitment_timelock_abs_split,
            commitment_timelock_abs_punish
        )?;

        let split_transaction = new_unsigned_transaction_split_final(
            &commitment_transaction.txid(),
            0,
            split_return_amount,
            split_return_amount,
            &Address::p2wpkh(&pk_user.pk_sig, network)?,
            &Address::p2wpkh(&pk_blnd.pk_sig, network)?,
            commitment_timelock_abs_split
        );
        let split_sighash = SighashCache::new(&split_transaction).segwit_signature_hash(
            0,
            &commitment_script,
            commitment_output_amount,
            bitcoin::EcdsaSighashType::All
        )?;
        let split_sig_user = sign_transaction(
            &split_transaction,
            commitment_output_amount,
            &sk_user.sk_sig,
            &commitment_script
        )?;
        split_sig_user.write_channel(chan)?;
        chan.flush()?;
        let split_sig_blnd = Signature::read_channel(chan)?;
        split_sig_blnd.verify(&Message::from_slice(split_sighash.as_inner())?, &pk_blnd.pk_sig.inner)?;
        let split_transaction = compose_transaction_split(
            split_transaction,
            split_sig_user,
            split_sig_blnd,
            &commitment_script
        );
        split_transaction.verify(|_| Some(commitment_transaction.output[0].clone()))?;

        let commitment_sighash = SighashCache::new(&commitment_transaction).segwit_signature_hash(
            0,
            &funding_script,
            funding_output_amount,
            bitcoin::EcdsaSighashType::All
        )?;
        let commitment_presig_user = AdaptorSignature::sign(
            &pk_blnd.pk_pub,
            commitment_sighash.as_inner(),
            &sk_user.sk_sig
        );
        commitment_presig_user.write_channel(chan)?;
        chan.flush()?;
        let commitment_presig_blnd = AdaptorSignature::read_channel(chan)?;
        commitment_presig_blnd.pre_verify(
            &pk_user.pk_pub,
            &commitment_sighash.as_inner(),
            &pk_blnd.pk_sig
        )?;
        let commitment_sig_blnd = commitment_presig_blnd.adapt(
            &sk_user.sk_pub
        )?;

        let commitment_sig_user = sign_transaction(&commitment_transaction,
            funding_output_amount,
            &sk_user.sk_sig,
            &funding_script
        )?;
        let commitment_transaction = compose_transaction_multisig(
            commitment_transaction,
            commitment_sig_user,
            commitment_sig_blnd,
            &funding_script
        );

        commitment_transaction.verify(|_| Some(funding_transaction_unsigned.output[0].clone()))
            .map_err(|_| anyhow::anyhow!("invlid commitment transaction signature"))?;
        split_transaction.verify(|_| Some(commitment_transaction.output[0].clone()))
            .map_err(|_| anyhow::anyhow!("invlid split transaction signature"))?;

        let funding_part_user = funding_signer.sign_transaction(funding_transaction_unsigned)?;
        funding_part_user.write_channel(chan)?;
        chan.flush()?;
        let funding_part_blnd = Transaction::read_channel(chan)?;
        let funding_transaction = compose_transaction_funding(funding_part_user, funding_part_blnd)?;

        let params = ChannelParams{
            funding_transaction,
            funding_script,
            commitment_output_amount,
            commitment_timelock_relative_split: commitment_timelock_abs_split,
            commitment_timelock_relative_punish: commitment_timelock_abs_punish,
            timeout_sequence
        };
        let status = ChannelStatus::SplitFinal {
            rev_cred_this: rev_cred_user,
            rev_hash_other: rev_hash_blnd,
            commitment_transaction, 
            commitment_transaction_presig_other: commitment_presig_blnd,
            split_transaction
        };

        let commitment_amount_user_randomness = FieldScalar::random();
        let commitment_amount_blnd_randomness = FieldScalar::random();
        G1Point::base_point2().scalar_mul(&commitment_amount_user_randomness).write_channel(chan)?;
        G1Point::base_point2().scalar_mul(&commitment_amount_blnd_randomness).write_channel(chan)?;
        chan.flush()?;
        // dbg!(crate::rsohc::commit_with_randomness(&FieldScalar::from_bigint(&split_return_amount.into()), &commitment_amount_user_randomness));
        // dbg!(crate::rsohc::commit_with_randomness(&FieldScalar::from_bigint(&split_return_amount.into()), &commitment_amount_blnd_randomness));
        
        Ok(Self{
            sk_user,
            pk_user,
            pk_blnd,
            params,
            status,
            commitment_amount_user_randomness,
            commitment_amount_blnd_randomness
        })
    }

    pub fn make_transfer<C: AbstractChannel>(
        &mut self,
        circ: &Circuit,
        f: &mut Evaluator<C, AesRng, NaorPinkasReceiver>,
        user_role: ChannelUserRole,
        transfer_amount: u64,
        payback_amount_user: u64,
        payback_amount_blnd: u64,
        puzzle_statement: &Secp256k1Point,
        fee: u64,
        network: Network,
        commitment_transfer_amount_randomness: &FieldScalar,
        commitment_payback_amount_user_randomness: &FieldScalar,
        commitment_payback_amount_blnd_randomness: &FieldScalar,
    ) -> anyhow::Result<()>{
        let (previous_rev_cred_this, previous_rev_hash_other) = match self.status {
            ChannelStatus::SplitFinal {rev_cred_this, rev_hash_other, ..} => Ok((rev_cred_this, rev_hash_other)),
            ChannelStatus::SplitDeliv {..}=> Err(anyhow::anyhow!("invalid status"))
        }?;

        let BuildCommitmentResult{
            rev_cred_user,
            rev_hash_blnd,
            commitment_script,
            commitment_transaction
        } = Self::build_unsigned_commitment_transaction(
            f.get_channel(),
            &self.params.funding_transaction.txid(),
            &self.pk_user,
            &self.pk_blnd,
            self.params.commitment_output_amount,
            self.params.commitment_timelock_relative_split,
            self.params.commitment_timelock_relative_punish
        )?;
        
        let DeliveryTransactionPack{
            split_script,
            split_transaction,
            aed_transaction,
            timeout_transaction,
        } = DeliveryTransactionPack::build(
            &user_role,
            &self.pk_user,
            &self.pk_blnd,
            network,
            &commitment_transaction.txid(),
            self.params.commitment_timelock_relative_split,
            transfer_amount,
            payback_amount_user,
            payback_amount_blnd,
            transfer_amount - fee,
            self.params.timeout_sequence
        )?;

        prove_all_transactions(
            circ,
            f,
            &split_transaction,
            &aed_transaction,
            &timeout_transaction,
            &commitment_script,
            &split_script,
            self.params.commitment_output_amount,
            fee,
            &commitment_transfer_amount_randomness,
            &commitment_payback_amount_user_randomness,
            &commitment_payback_amount_blnd_randomness
        )?;

        let aed_transaction_sighash = SighashCache::new(&aed_transaction).segwit_signature_hash(0, &split_script, transfer_amount, bitcoin::EcdsaSighashType::All)?;
        let timeout_transaction_sighash = SighashCache::new(&timeout_transaction).segwit_signature_hash(0, &split_script, transfer_amount, bitcoin::EcdsaSighashType::All)?;

        let (aed_transaction_presig, timeout_transaction) = match user_role {
            ChannelUserRole::Payer => {
                let aed_transaction_presig_user = AdaptorSignature::sign_kzen(
                    &puzzle_statement,
                    &aed_transaction_sighash.as_inner(),
                    &Secp256k1Scalar::from_underlying(Some(secp256_k1::SK(self.sk_user.sk_sig)))
                );
                aed_transaction_presig_user.write_channel(f.get_channel())?;
                f.get_channel().flush()?;
                let timtout_transaction_sig_user = self.sk_user.sk_sig.sign_ecdsa(
                    Message::from_slice(&timeout_transaction_sighash)?
                );
                // timtout_transaction_sig_user.write_channel(f.get_channel())?;
                let timtout_transaction_sig_blnd = Signature::read_channel(f.get_channel())?;
                let timeout_transaction = compose_transaction_multisig(
                    timeout_transaction,
                    timtout_transaction_sig_user,
                    timtout_transaction_sig_blnd,
                    &split_script
                );
                timeout_transaction.verify(|_| Some(split_transaction.output[0].clone())).map_err(
                    |e| anyhow::anyhow!("invalid signature for timeout transaction, {}", e.to_string())
                )?;
                (None, Some(timeout_transaction))
            },
            ChannelUserRole::Payee => {
                let aed_transaction_presig_blnd = AdaptorSignature::read_channel(f.get_channel())?;
                aed_transaction_presig_blnd.pre_verify_kzen(
                    &puzzle_statement,
                    &aed_transaction_sighash.as_inner(),
                    &Secp256k1Point::from_underlying(Some(secp256_k1::PK(self.pk_blnd.pk_sig.inner)))
                )?;
                let timtout_transaction_sig_user = self.sk_user.sk_sig.sign_ecdsa(
                    Message::from_slice(&timeout_transaction_sighash)?
                );
                timtout_transaction_sig_user.write_channel(f.get_channel())?;
                f.get_channel().flush()?;
                // let timtout_transaction_sig_blnd = Signature::read_channel(f.get_channel())?;
                (Some(aed_transaction_presig_blnd), None)
            }
        };

        // let transaction_pay_blnd_sighash = SighashCache::new(
        //     user_role.pay_blnd_transaction(&aed_transaction, &timeout_transaction)
        // ).segwit_signature_hash(0, &split_script, transfer_amount, bitcoin::EcdsaSighashType::All)?;

        // dbg!(&transaction_pay_blnd_sighash);

        // let transaction_pay_user_sighash = SighashCache::new(
        //     user_role.pay_user_transaction(&aed_transaction, &timeout_transaction)
        // ).segwit_signature_hash(0, &split_script, transfer_amount, bitcoin::EcdsaSighashType::All)?;
        // dbg!(&transaction_pay_user_sighash);

        // let transaction_pay_blnd_presig = AdaptorSignature::sign_kzen(
        //     &puzzle_statement,
        //     transaction_pay_blnd_sighash.as_inner(),
        //     &Secp256k1Scalar::from_underlying(Some(secp256_k1::SK(self.sk_user.sk_sig)))
        // );
        // transaction_pay_blnd_presig.write_channel(f.get_channel())?;
        // let transaction_pay_user_sig_blnd = Signature::read_channel(f.get_channel())?;
        // let transaction_pay_user_sig_user = self.sk_user.sk_sig.sign_ecdsa(
        //     Message::from_slice(transaction_pay_user_sighash.as_inner())?
        // );
        // let (aed_transaction, timeout_transaction) = {
        //     match user_role {
        //         ChannelUserRole::Payer => {
        //             let timeout_transaction = compose_transaction_multisig(
        //                 timeout_transaction,
        //                 transaction_pay_user_sig_user,
        //                 transaction_pay_user_sig_blnd,
        //                 &split_script
        //             );
        //             timeout_transaction.verify(|_| Some(split_transaction.output[0].clone())).map_err(
        //                 |e| anyhow::anyhow!("invalid signature for timeout transaction, {}", e.to_string())
        //             )?;
        //             (aed_transaction, timeout_transaction)
        //         },
        //         ChannelUserRole::Payee => {
        //             let aed_transaction = compose_transaction_multisig(
        //                 aed_transaction,
        //                 transaction_pay_user_sig_user,
        //                 transaction_pay_user_sig_blnd,
        //                 &split_script
        //             );
        //             aed_transaction.verify(|_| Some(split_transaction.output[0].clone())).map_err(
        //                 |e| anyhow::anyhow!("invalid signature for executive transaction, {}", e.to_string())
        //             )?;
        //             (aed_transaction, timeout_transaction)
        //         },
        //     }
        // };
        let split_transaction_sig_user = self.sk_user.sk_sig.sign_ecdsa(Message::from_slice(
            SighashCache::new(&split_transaction).segwit_signature_hash(
                0,
                &commitment_script,
                self.params.commitment_output_amount,
                bitcoin::EcdsaSighashType::All
            )?.as_inner()
        )?);
        let split_transaction_sig_blnd = Signature::read_channel(f.get_channel())?;
        let split_transaction = compose_transaction_split(
            split_transaction,
            split_transaction_sig_user,
            split_transaction_sig_blnd,
            &commitment_script
        );
        split_transaction.verify(|_| Some(commitment_transaction.output[0].clone())).map_err(
            |e| anyhow::anyhow!("invalid signature for split transaction, {}", e.to_string())
        )?;

        let commitment_transaction_presig_user = AdaptorSignature::sign(
            &self.pk_blnd.pk_pub,
            SighashCache::new(&commitment_transaction).segwit_signature_hash(
                0,
                &self.params.funding_script,
                self.params.funding_transaction.output[0].value,
                bitcoin::EcdsaSighashType::All
            )?.as_inner(),
            &self.sk_user.sk_sig
        );
        commitment_transaction_presig_user.write_channel(f.get_channel())?;
        f.get_channel().flush()?;
        let commitment_transaction_presig_blnd = AdaptorSignature::read_channel(f.get_channel())?;
        commitment_transaction_presig_blnd.pre_verify(
            &self.pk_user.pk_pub,
            SighashCache::new(&commitment_transaction).segwit_signature_hash(
                0,
                &self.params.funding_script,
                self.params.funding_transaction.output[0].value,
                bitcoin::EcdsaSighashType::All
            )?.as_inner(),
            &self.pk_blnd.pk_sig
        )?;
        let commitment_transaction_sig_blnd = commitment_transaction_presig_blnd.adapt(
            &self.sk_user.sk_pub
        )?;
        let commitment_transaction_sig_user = self.sk_user.sk_sig.sign_ecdsa(Message::from_slice(
            SighashCache::new(&commitment_transaction).segwit_signature_hash(
                0,
                &self.params.funding_script,
                self.params.funding_transaction.output[0].value,
                bitcoin::EcdsaSighashType::All
            )?.as_inner()
        )?);
        let commitment_transaction = compose_transaction_multisig(
            commitment_transaction,
            commitment_transaction_sig_user,
            commitment_transaction_sig_blnd,
            &self.params.funding_script
        );
        commitment_transaction.verify(|_| Some(self.params.funding_transaction.output[0].clone()))?;

        previous_rev_cred_this.write_channel(f.get_channel())?;
        f.get_channel().flush()?;
        let previous_rev_cred_other = SecretKey::read_channel(f.get_channel())?;
        let previous_rev_hash_other_comp: [u8;32] =  Sha256::digest(&Sha256::digest(previous_rev_cred_other.as_ref())).try_into()?;
        if previous_rev_hash_other != previous_rev_hash_other_comp {
            return Err(anyhow::anyhow!("invalid revocation key received"))
        }

        self.status = ChannelStatus::SplitDeliv {
            user_role,
            rev_cred_this: rev_cred_user,
            rev_hash_other: rev_hash_blnd,
            commitment_transaction,
            commitment_transaction_presig_other: commitment_transaction_presig_blnd,
            split_script,
            split_transaction,
            aed_transaction_sighash: aed_transaction_sighash.as_inner().to_owned(),
            aed_transaction_presig,
            aed_transaction,
            timeout_transaction
        };
        
        Ok(())
    }

    pub fn complete_aed_trnasaction(&mut self, witness: &Secp256k1Scalar) -> anyhow::Result<()>{
        match &mut self.status {
            ChannelStatus::SplitFinal {
                ..
            } => return Err(anyhow::anyhow!("invalid status split final")),
            ChannelStatus::SplitDeliv {
                split_script,
                split_transaction,
                aed_transaction_sighash,
                aed_transaction_presig,
                aed_transaction,
                ..
            } => {
                let aed_transaction_presig_blnd = aed_transaction_presig.as_ref().ok_or(anyhow::anyhow!("aed transaction presig not found"))?;
                let aed_transaction_sig_blnd = aed_transaction_presig_blnd.adapt_kzen(witness)?;
                let aed_transaction_sig_user = self.sk_user.sk_sig.sign_ecdsa(
                    Message::from_slice(aed_transaction_sighash)?
                );
                *aed_transaction = compose_transaction_multisig(
                    aed_transaction.clone(),
                    aed_transaction_sig_user,
                    aed_transaction_sig_blnd,
                    &split_script
                );
                aed_transaction.verify(
                    |_| Some(split_transaction.output[0].clone())
                )?;
            },
        }
        Ok(())
    }

    pub fn reduce<C: AbstractChannel>(
        &mut self,
        circ: &Circuit,
        f: &mut Evaluator<C, AesRng, NaorPinkasReceiver>,
        network: Network,
        payback_amount_user: u64,
        payback_amount_blnd: u64,
        commitment_payback_amount_user_randomness: &FieldScalar,
        commitment_payback_amount_blnd_randomness: &FieldScalar,
    ) -> anyhow::Result<()> {
        let (previous_rev_cred_this, previous_rev_hash_other) = match self.status {
            ChannelStatus::SplitDeliv {rev_cred_this, rev_hash_other, ..} => Ok((rev_cred_this, rev_hash_other)),
            ChannelStatus::SplitFinal {..}=> Err(anyhow::anyhow!("invalid status"))
        }?;

        let BuildCommitmentResult{
            rev_cred_user,
            rev_hash_blnd,
            commitment_script,
            commitment_transaction
        } = Self::build_unsigned_commitment_transaction(
            f.get_channel(),
            &self.params.funding_transaction.txid(),
            &self.pk_user,
            &self.pk_blnd,
            self.params.commitment_output_amount,
            self.params.commitment_timelock_relative_split,
            self.params.commitment_timelock_relative_punish
        )?;

        let split_transaction = new_unsigned_transaction_split_final(
            &commitment_transaction.txid(),
            0,
            payback_amount_user,
            payback_amount_blnd,
            &Address::p2wpkh(&self.pk_user.pk_sig, network)?,
            &Address::p2wpkh(&self.pk_blnd.pk_sig, network)?,
            self.params.commitment_timelock_relative_split
        );

        prove_split_final_transaction(
            circ,
            f,
            &split_transaction,
            &commitment_script,
            self.params.commitment_output_amount,
            &commitment_payback_amount_user_randomness,
            &commitment_payback_amount_blnd_randomness
        )?;

        let split_transaction_sig_user = self.sk_user.sk_sig.sign_ecdsa(Message::from_slice(
            SighashCache::new(&split_transaction).segwit_signature_hash(
                0,
                &commitment_script,
                self.params.commitment_output_amount,
                bitcoin::EcdsaSighashType::All
            )?.as_inner()
        )?);
        let split_transaction_sig_blnd = Signature::read_channel(f.get_channel())?;
        let split_transaction = compose_transaction_split(
            split_transaction,
            split_transaction_sig_user,
            split_transaction_sig_blnd,
            &commitment_script
        );
        split_transaction.verify(|_| Some(commitment_transaction.output[0].clone())).map_err(
            |e| anyhow::anyhow!("invalid signature for split transaction, {}", e.to_string())
        )?;

        let commitment_transaction_presig_user = AdaptorSignature::sign(
            &self.pk_blnd.pk_pub,
            SighashCache::new(&commitment_transaction).segwit_signature_hash(
                0,
                &self.params.funding_script,
                self.params.funding_transaction.output[0].value,
                bitcoin::EcdsaSighashType::All
            )?.as_inner(),
            &self.sk_user.sk_sig
        );
        commitment_transaction_presig_user.write_channel(f.get_channel())?;
        f.get_channel().flush()?;
        let commitment_transaction_presig_blnd = AdaptorSignature::read_channel(f.get_channel())?;
        commitment_transaction_presig_blnd.pre_verify(
            &self.pk_user.pk_pub,
            SighashCache::new(&commitment_transaction).segwit_signature_hash(
                0,
                &self.params.funding_script,
                self.params.funding_transaction.output[0].value,
                bitcoin::EcdsaSighashType::All
            )?.as_inner(),
            &self.pk_blnd.pk_sig
        )?;
        let commitment_transaction_sig_blnd = commitment_transaction_presig_blnd.adapt(
            &self.sk_user.sk_pub
        )?;
        let commitment_transaction_sig_user = self.sk_user.sk_sig.sign_ecdsa(Message::from_slice(
            SighashCache::new(&commitment_transaction).segwit_signature_hash(
                0,
                &self.params.funding_script,
                self.params.funding_transaction.output[0].value,
                bitcoin::EcdsaSighashType::All
            )?.as_inner()
        )?);
        let commitment_transaction = compose_transaction_multisig(
            commitment_transaction,
            commitment_transaction_sig_user,
            commitment_transaction_sig_blnd,
            &self.params.funding_script
        );
        commitment_transaction.verify(|_| Some(self.params.funding_transaction.output[0].clone()))?;

        split_transaction.verify(|_| Some(commitment_transaction.output[0].clone()))?;

        previous_rev_cred_this.write_channel(f.get_channel())?;
        f.get_channel().flush()?;
        let previous_rev_cred_other = SecretKey::read_channel(f.get_channel())?;
        let previous_rev_hash_other_comp: [u8;32] =  Sha256::digest(&Sha256::digest(previous_rev_cred_other.as_ref())).try_into()?;
        if previous_rev_hash_other != previous_rev_hash_other_comp {
            return Err(anyhow::anyhow!("invalid revocation key received"))
        }

        self.status = ChannelStatus::SplitFinal {
            rev_cred_this: rev_cred_user,
            rev_hash_other: rev_hash_blnd,
            commitment_transaction,
            commitment_transaction_presig_other: commitment_transaction_presig_blnd,
            split_transaction,
        };

        Ok(())
    }
}