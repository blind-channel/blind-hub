use bitcoin::{Transaction, Script, Txid, Network, secp256k1::{SecretKey, ecdsa::Signature, Message}, Address, util::sighash::SighashCache, hashes::Hash};
use curv::elliptic::curves::{secp256_k1::{Secp256k1Scalar, Secp256k1Point, self}, ECScalar, ECPoint, bls12_381::{g1::G1Point, scalar::FieldScalar}};
use fancy_garbling::{circuit::Circuit, twopac::semihonest::Garbler};
use ocelot::ot::NaorPinkasSender;
use scuttlebutt::{AbstractChannel, AesRng};
use sha2::{Sha256, Digest};

use crate::{transaction::{new_unsigned_transcation_funding, new_unsigned_transcation_commitement, new_unsigned_transaction_split_final, sign_transaction, compose_transaction_split, compose_transaction_multisig, compose_transaction_funding}, script::{new_commitment_script, new_funding_script}, ecdsa::AdaptorSignature, zkgc::{verify_all_transactions, verify_split_final_transaction}};

use super::{ChannelParams, ChannelStatus, ChannelSK, ChannelPK, FundingSigner, Transferable, ChannelUserRole, DeliveryTransactionPack};

#[derive(Clone)]
pub struct ChannelBlind{
    pub params: ChannelParams,
    pub status: ChannelStatus,
    pub sk_blnd: ChannelSK,
    pub pk_user: ChannelPK,
    pub pk_blnd: ChannelPK,
    pub commitment_amount_blnd: G1Point,
    pub commitment_amount_user: G1Point
}

struct BuildCommitmentResult {
    rev_cred_blnd: SecretKey,
    rev_hash_user: [u8;32],
    commitment_script: Script,
    commitment_transaction: Transaction
}

impl ChannelBlind {
    fn build_unsigned_funding_transaction<C: AbstractChannel>(
        chan: &mut C,
        funding_template_blnd: Transaction,
        funding_script: &Script,
        funding_output_amount: u64
    ) -> anyhow::Result<Transaction> {
        funding_template_blnd.write_channel(chan)?;
        chan.flush()?;
        let funding_template_user = Transaction::read_channel(chan)?;
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
        let rev_cred_blnd = Secp256k1Scalar::random().underlying_ref().clone().unwrap().0.clone();
        let rev_hash_blnd: [u8;32] = Sha256::digest(&Sha256::digest(&rev_cred_blnd.as_ref())).try_into()?;
        chan.write_bytes(&rev_hash_blnd)?;
        chan.flush()?;
        let mut rev_hash_user = [0u8;32];
        chan.read_bytes(&mut rev_hash_user)?;

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

        Ok(BuildCommitmentResult{
            rev_cred_blnd,
            rev_hash_user,
            commitment_script,
            commitment_transaction,
        })
    }
    
    pub fn new<C: AbstractChannel, S: FundingSigner>(
        chan: &mut C,
        network: Network,
        funding_signer: &S,
        funding_template_blnd: Transaction,
        funding_output_amount: u64,
        commitment_output_amount: u64,
        split_return_amount: u64,
        commitment_timelock_abs_split: u32,
        commitment_timelock_abs_punish: u32,
        timeout_sequence: u32
    ) -> anyhow::Result<Self> {
        let sk_blnd = ChannelSK::new();
        let pk_blnd = ChannelPK::from_sk(&sk_blnd);
        pk_blnd.write_channel(chan)?;
        chan.flush()?;
        let pk_user = ChannelPK::read_channel(chan)?;

        let funding_script = new_funding_script(
            &pk_user.pk_sig,
            &pk_blnd.pk_sig
        );
        let funding_transaction_unsigned = Self::build_unsigned_funding_transaction(
            chan,
            funding_template_blnd,
            &funding_script,
            funding_output_amount
        )?;

        let BuildCommitmentResult{
            rev_cred_blnd,
            rev_hash_user,
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
        let split_sig_blnd = sign_transaction(
            &split_transaction,
            commitment_output_amount,
            &sk_blnd.sk_sig,
            &commitment_script
        )?;
        split_sig_blnd.write_channel(chan)?;
        chan.flush()?;
        let split_sig_user = Signature::read_channel(chan)?;
        split_sig_user.verify(&Message::from_slice(split_sighash.as_inner())?, &pk_user.pk_sig.inner)?;
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
        let commitment_presig_blnd = AdaptorSignature::sign(
            &pk_user.pk_pub,
            commitment_sighash.as_inner(),
            &sk_blnd.sk_sig
        );
        commitment_presig_blnd.write_channel(chan)?;
        chan.flush()?;
        let commitment_presig_user = AdaptorSignature::read_channel(chan)?;
        commitment_presig_user.pre_verify(
            &pk_blnd.pk_pub,
            &commitment_sighash.as_inner(),
            &pk_user.pk_sig
        )?;
        let commitment_sig_user = commitment_presig_user.adapt(
            &sk_blnd.sk_pub
        )?;
        let commitment_sig_blnd = sign_transaction(&commitment_transaction,
            funding_output_amount,
            &sk_blnd.sk_sig,
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

        let funding_part_blnd = funding_signer.sign_transaction(funding_transaction_unsigned)?;
        funding_part_blnd.write_channel(chan)?;
        chan.flush()?;
        let funding_part_user = Transaction::read_channel(chan)?;
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
            rev_cred_this: rev_cred_blnd,
            rev_hash_other: rev_hash_user,
            commitment_transaction, 
            commitment_transaction_presig_other: commitment_presig_blnd,
            split_transaction
        };

        let commitment_amount_user = G1Point::read_channel(chan)?.add_point(&G1Point::generator_mul(
            &FieldScalar::from_bigint(&split_return_amount.into())
        ));
        let commitment_amount_blnd = G1Point::read_channel(chan)?.add_point(&G1Point::generator_mul(
            &FieldScalar::from_bigint(&split_return_amount.into())
        ));
        // dbg!(&commitment_amount_user);
        // dbg!(&commitment_amount_blnd);
        
        Ok(Self{
            sk_blnd,
            pk_user,
            pk_blnd,
            params,
            status,
            commitment_amount_user,
            commitment_amount_blnd
        })
    }

    pub fn make_transfer<C: AbstractChannel>(
        &mut self,
        circ: &Circuit,
        f: &mut Garbler<C, AesRng, NaorPinkasSender>,
        user_role: ChannelUserRole,
        puzzle_statement: &Secp256k1Point,
        fee: u64,
        network: Network,
        commitment_transfer_amount: &G1Point,
        commitment_payback_amount_user: &G1Point,
        commitment_payback_amount_blnd: &G1Point
    ) -> anyhow::Result<()>{
        let (previous_rev_cred_this, previous_rev_hash_other) = match self.status {
            ChannelStatus::SplitFinal {rev_cred_this, rev_hash_other, ..} => Ok((rev_cred_this, rev_hash_other)),
            ChannelStatus::SplitDeliv {..}=> Err(anyhow::anyhow!("invalid status"))
        }?;

        let BuildCommitmentResult{
            rev_cred_blnd,
            rev_hash_user,
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
            0,
            0,
            0,
            0,
            self.params.timeout_sequence
        )?;

        let sighash_list = verify_all_transactions(
            circ,
            f,
            &split_transaction,
            &aed_transaction,
            &timeout_transaction,
            &commitment_script,
            &split_script,
            self.params.commitment_output_amount,
            fee,
            &commitment_transfer_amount,
            &commitment_payback_amount_user,
            &commitment_payback_amount_blnd
        )?;

        let (aed_transaction_presig, timeout_transaction) = match user_role {
            ChannelUserRole::Payer => {
                let aed_transaction_presig_user = AdaptorSignature::read_channel(f.get_channel())?;
                aed_transaction_presig_user.pre_verify_kzen(
                    &puzzle_statement,
                    &sighash_list.sighash_txaed,
                    &Secp256k1Point::from_underlying(Some(secp256_k1::PK(self.pk_user.pk_sig.inner)))
                )?;
                let timtout_transaction_sig_blnd = self.sk_blnd.sk_sig.sign_ecdsa(
                    Message::from_slice(&sighash_list.sighash_tmout)?
                );
                timtout_transaction_sig_blnd.write_channel(f.get_channel())?;
                f.get_channel().flush()?;
                // let timtout_transaction_sig_user = Signature::read_channel(f.get_channel())?;
                (Some(aed_transaction_presig_user), None)
            },
            ChannelUserRole::Payee => {
                let aed_transaction_presig_blnd = AdaptorSignature::sign_kzen(
                    &puzzle_statement,
                    &sighash_list.sighash_txaed,
                    &Secp256k1Scalar::from_underlying(Some(secp256_k1::SK(self.sk_blnd.sk_sig)))
                );
                aed_transaction_presig_blnd.write_channel(f.get_channel())?;
                let timtout_transaction_sig_blnd = self.sk_blnd.sk_sig.sign_ecdsa(
                    Message::from_slice(&sighash_list.sighash_tmout)?
                );
                f.get_channel().flush()?;
                // timtout_transaction_sig_blnd.write_channel(f.get_channel())?;
                let timtout_transaction_sig_user = Signature::read_channel(f.get_channel())?;
                let timeout_transaction = compose_transaction_multisig(
                    timeout_transaction,
                    timtout_transaction_sig_user,
                    timtout_transaction_sig_blnd,
                    &split_script
                );
                timtout_transaction_sig_user.verify(
                    &Message::from_slice(&sighash_list.sighash_tmout)?,
                    &self.pk_user.pk_sig.inner
                )?;
                (None, Some(timeout_transaction))
            }
        };

        // let transaction_pay_user_sig = self.sk_blnd.sk_sig.sign_ecdsa(Message::from_slice(match user_role {
        //     ChannelUserRole::Payer => &sighash_list.sighash_tmout,
        //     ChannelUserRole::Payee => &sighash_list.sighash_txaed,
        // })?);
        // transaction_pay_user_sig.write_channel(f.get_channel())?;
        // dbg!(sighash_list.sighash_split.to_hex());
        let split_transaction_sig_blnd = self.sk_blnd.sk_sig.sign_ecdsa(Message::from_slice(&sighash_list.sighash_split)?);
        split_transaction_sig_blnd.write_channel(f.get_channel())?;

        let commitment_transaction_presig_blnd = AdaptorSignature::sign(
            &self.pk_user.pk_pub,
            SighashCache::new(&commitment_transaction).segwit_signature_hash(
                0,
                &self.params.funding_script,
                self.params.funding_transaction.output[0].value,
                bitcoin::EcdsaSighashType::All
            )?.as_inner(),
            &self.sk_blnd.sk_sig
        );
        commitment_transaction_presig_blnd.write_channel(f.get_channel())?;
        f.get_channel().flush()?;
        let commitment_transaction_presig_user = AdaptorSignature::read_channel(f.get_channel())?;
        commitment_transaction_presig_user.pre_verify(
            &self.pk_blnd.pk_pub,
            SighashCache::new(&commitment_transaction).segwit_signature_hash(
                0,
                &self.params.funding_script,
                self.params.funding_transaction.output[0].value,
                bitcoin::EcdsaSighashType::All
            )?.as_inner(),
            &self.pk_user.pk_sig
        )?;
        let commitment_transaction_sig_user = commitment_transaction_presig_user.adapt(
            &self.sk_blnd.sk_pub
        )?;
        let commitment_transaction_sig_blnd = self.sk_blnd.sk_sig.sign_ecdsa(Message::from_slice(
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
            rev_cred_this: rev_cred_blnd,
            rev_hash_other: rev_hash_user,
            commitment_transaction,
            commitment_transaction_presig_other: commitment_transaction_presig_user,
            split_script,
            split_transaction,
            aed_transaction_sighash: sighash_list.sighash_txaed,
            aed_transaction_presig,
            aed_transaction,
            timeout_transaction,
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
                aed_transaction_sighash,
                aed_transaction_presig,
                aed_transaction,
                ..
            } => {
                let aed_transaction_presig_user = aed_transaction_presig.as_ref().ok_or(anyhow::anyhow!("aed transaction presig not found"))?;
                let aed_transaction_sig_user = aed_transaction_presig_user.adapt_kzen(witness)?;
                let aed_transaction_sig_blnd = self.sk_blnd.sk_sig.sign_ecdsa(
                    Message::from_slice(aed_transaction_sighash)?
                );
                aed_transaction_sig_user.verify(
                    &Message::from_slice(aed_transaction_sighash)?,
                    &self.pk_user.pk_sig.inner
                )?;
                *aed_transaction = compose_transaction_multisig(
                    aed_transaction.clone(),
                    aed_transaction_sig_user,
                    aed_transaction_sig_blnd,
                    &split_script
                );
            },
        }
        Ok(())
    }

    pub fn reduce<C: AbstractChannel>(
        &mut self,
        circ: &Circuit,
        f: &mut Garbler<C, AesRng, NaorPinkasSender>,
        network: Network,
        commitment_payback_amount_user: &G1Point,
        commitment_payback_amount_blnd: &G1Point
    ) -> anyhow::Result<()> {
        let (previous_rev_cred_this, previous_rev_hash_other) = match self.status {
            ChannelStatus::SplitDeliv {rev_cred_this, rev_hash_other, ..} => Ok((rev_cred_this, rev_hash_other)),
            ChannelStatus::SplitFinal {..}=> Err(anyhow::anyhow!("invalid status"))
        }?;

        let BuildCommitmentResult{
            rev_cred_blnd,
            rev_hash_user,
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
            0,
            0,
            &Address::p2wpkh(&self.pk_user.pk_sig, network)?,
            &Address::p2wpkh(&self.pk_blnd.pk_sig, network)?,
            self.params.commitment_timelock_relative_split
        );

        let sighash_split = verify_split_final_transaction(
            circ,
            f,
            &split_transaction,
            &commitment_script,
            self.params.commitment_output_amount,
            &commitment_payback_amount_user,
            &commitment_payback_amount_blnd
        )?;

        let split_transaction_sig_blnd = self.sk_blnd.sk_sig.sign_ecdsa(Message::from_slice(&sighash_split)?);
        split_transaction_sig_blnd.write_channel(f.get_channel())?;

        let commitment_transaction_presig_blnd = AdaptorSignature::sign(
            &self.pk_user.pk_pub,
            SighashCache::new(&commitment_transaction).segwit_signature_hash(
                0,
                &self.params.funding_script,
                self.params.funding_transaction.output[0].value,
                bitcoin::EcdsaSighashType::All
            )?.as_inner(),
            &self.sk_blnd.sk_sig
        );
        commitment_transaction_presig_blnd.write_channel(f.get_channel())?;
        f.get_channel().flush()?;
        let commitment_transaction_presig_user = AdaptorSignature::read_channel(f.get_channel())?;
        commitment_transaction_presig_user.pre_verify(
            &self.pk_blnd.pk_pub,
            SighashCache::new(&commitment_transaction).segwit_signature_hash(
                0,
                &self.params.funding_script,
                self.params.funding_transaction.output[0].value,
                bitcoin::EcdsaSighashType::All
            )?.as_inner(),
            &self.pk_user.pk_sig
        )?;
        let commitment_transaction_sig_user = commitment_transaction_presig_user.adapt(
            &self.sk_blnd.sk_pub
        )?;
        let commitment_transaction_sig_blnd = self.sk_blnd.sk_sig.sign_ecdsa(Message::from_slice(
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

        self.status = ChannelStatus::SplitFinal {
            rev_cred_this: rev_cred_blnd,
            rev_hash_other: rev_hash_user,
            commitment_transaction,
            commitment_transaction_presig_other: commitment_transaction_presig_user,
            split_transaction,
        };

        Ok(())
    }
}