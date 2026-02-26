use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{self, Mint, Token, TokenAccount, Transfer},
};

declare_id!("Fg6PaFpoGXkYsidMpWxTWqkYb6W3uPSEBm1D6T9Q7d7");

#[program]
pub mod premium_billing {
    use super::*;

    pub fn initialize_config(
        ctx: Context<InitializeConfig>,
        free_grant_amount: u64,
        points_per_token: u64,
    ) -> Result<()> {
        require!(free_grant_amount > 0, PremiumError::InvalidAmount);
        require!(points_per_token > 0, PremiumError::InvalidPointsRate);

        let cfg = &mut ctx.accounts.config;
        cfg.authority = ctx.accounts.authority.key();
        cfg.mint = ctx.accounts.mint.key();
        cfg.vault = ctx.accounts.vault.key();
        cfg.free_grant_amount = free_grant_amount;
        cfg.points_per_token = points_per_token;
        cfg.paused = false;
        cfg.bump = ctx.bumps.config;

        emit!(ConfigInitialized {
            authority: cfg.authority,
            mint: cfg.mint,
            vault: cfg.vault,
            free_grant_amount,
            points_per_token,
            at: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    pub fn update_config(
        ctx: Context<UpdateConfig>,
        free_grant_amount: u64,
        points_per_token: u64,
        paused: bool,
    ) -> Result<()> {
        require!(free_grant_amount > 0, PremiumError::InvalidAmount);
        require!(points_per_token > 0, PremiumError::InvalidPointsRate);

        let cfg = &mut ctx.accounts.config;
        cfg.free_grant_amount = free_grant_amount;
        cfg.points_per_token = points_per_token;
        cfg.paused = paused;

        emit!(ConfigUpdated {
            authority: cfg.authority,
            free_grant_amount,
            points_per_token,
            paused,
            at: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn grant_free_session(
        ctx: Context<GrantFreeSession>,
        session_hash: [u8; 32],
        grant_amount: u64,
    ) -> Result<()> {
        let cfg = &ctx.accounts.config;
        require!(!cfg.paused, PremiumError::BillingPaused);

        let now = Clock::get()?.unix_timestamp;
        let ledger = &mut ctx.accounts.ledger;
        init_or_validate_ledger(
            ledger,
            cfg.key(),
            ctx.accounts.user.key(),
            session_hash,
            ctx.bumps.ledger,
            now,
        )?;

        require!(!ledger.free_grant_claimed, PremiumError::FreeGrantAlreadyClaimed);

        let amount = if grant_amount == 0 {
            cfg.free_grant_amount
        } else {
            grant_amount
        };
        require!(amount > 0, PremiumError::InvalidAmount);

        let signer_seeds: &[&[&[u8]]] = &[&[b"config", &[cfg.bump]]];
        let cpi_accounts = Transfer {
            from: ctx.accounts.vault.to_account_info(),
            to: ctx.accounts.user_token_account.to_account_info(),
            authority: ctx.accounts.config.to_account_info(),
        };
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                cpi_accounts,
                signer_seeds,
            ),
            amount,
        )?;

        ledger.free_grant_claimed = true;
        ledger.total_granted = ledger
            .total_granted
            .checked_add(amount)
            .ok_or(PremiumError::MathOverflow)?;
        ledger.last_updated_at = now;

        emit!(FreeSessionGranted {
            user: ledger.user,
            session_hash,
            amount,
            points_equivalent: amount
                .checked_mul(cfg.points_per_token)
                .ok_or(PremiumError::MathOverflow)?,
            at: now,
        });

        Ok(())
    }

    pub fn charge_premium(
        ctx: Context<ChargePremium>,
        session_hash: [u8; 32],
        token_amount: u64,
        points_equivalent: u64,
    ) -> Result<()> {
        let cfg = &ctx.accounts.config;
        require!(!cfg.paused, PremiumError::BillingPaused);
        require!(token_amount > 0, PremiumError::InvalidAmount);

        let now = Clock::get()?.unix_timestamp;
        let ledger = &mut ctx.accounts.ledger;
        init_or_validate_ledger(
            ledger,
            cfg.key(),
            ctx.accounts.user.key(),
            session_hash,
            ctx.bumps.ledger,
            now,
        )?;

        let cpi_accounts = Transfer {
            from: ctx.accounts.user_token_account.to_account_info(),
            to: ctx.accounts.vault.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        token::transfer(
            CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts),
            token_amount,
        )?;

        ledger.total_spent = ledger
            .total_spent
            .checked_add(token_amount)
            .ok_or(PremiumError::MathOverflow)?;
        ledger.points_charged = ledger
            .points_charged
            .checked_add(points_equivalent)
            .ok_or(PremiumError::MathOverflow)?;
        ledger.last_updated_at = now;

        emit!(PremiumCharged {
            user: ledger.user,
            session_hash,
            token_amount,
            points_equivalent,
            at: now,
        });

        Ok(())
    }

    pub fn withdraw_from_vault(ctx: Context<WithdrawFromVault>, amount: u64) -> Result<()> {
        require!(amount > 0, PremiumError::InvalidAmount);

        let cfg = &ctx.accounts.config;
        let signer_seeds: &[&[&[u8]]] = &[&[b"config", &[cfg.bump]]];
        let cpi_accounts = Transfer {
            from: ctx.accounts.vault.to_account_info(),
            to: ctx.accounts.destination_token_account.to_account_info(),
            authority: ctx.accounts.config.to_account_info(),
        };

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                cpi_accounts,
                signer_seeds,
            ),
            amount,
        )?;

        emit!(VaultWithdrawn {
            authority: cfg.authority,
            destination: ctx.accounts.destination_token_account.key(),
            amount,
            at: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }
}

fn init_or_validate_ledger(
    ledger: &mut Account<SessionLedger>,
    config: Pubkey,
    user: Pubkey,
    session_hash: [u8; 32],
    bump: u8,
    now: i64,
) -> Result<()> {
    if ledger.created_at == 0 {
        ledger.config = config;
        ledger.user = user;
        ledger.session_hash = session_hash;
        ledger.total_granted = 0;
        ledger.total_spent = 0;
        ledger.points_charged = 0;
        ledger.free_grant_claimed = false;
        ledger.bump = bump;
        ledger.created_at = now;
        ledger.last_updated_at = now;
        return Ok(());
    }

    require_keys_eq!(ledger.config, config, PremiumError::LedgerMismatch);
    require_keys_eq!(ledger.user, user, PremiumError::LedgerMismatch);
    require!(ledger.session_hash == session_hash, PremiumError::LedgerMismatch);

    Ok(())
}

#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    pub mint: Account<'info, Mint>,

    #[account(
        init,
        payer = authority,
        seeds = [b"config"],
        bump,
        space = 8 + PremiumConfig::LEN
    )]
    pub config: Account<'info, PremiumConfig>,

    #[account(
        init,
        payer = authority,
        associated_token::mint = mint,
        associated_token::authority = config
    )]
    pub vault: Account<'info, TokenAccount>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump,
        has_one = authority,
    )]
    pub config: Account<'info, PremiumConfig>,
}

#[derive(Accounts)]
#[instruction(session_hash: [u8; 32], _grant_amount: u64)]
pub struct GrantFreeSession<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump,
        has_one = authority,
    )]
    pub config: Account<'info, PremiumConfig>,

    /// CHECK: Destination wallet for free grant.
    pub user: UncheckedAccount<'info>,

    #[account(
        init_if_needed,
        payer = authority,
        seeds = [b"ledger", config.key().as_ref(), user.key().as_ref(), &session_hash],
        bump,
        space = 8 + SessionLedger::LEN
    )]
    pub ledger: Account<'info, SessionLedger>,

    #[account(
        mut,
        address = config.vault,
        constraint = vault.owner == config.key() @ PremiumError::VaultAuthorityMismatch,
        constraint = vault.mint == config.mint @ PremiumError::InvalidMint,
    )]
    pub vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = user_token_account.owner == user.key() @ PremiumError::InvalidUserTokenAccount,
        constraint = user_token_account.mint == config.mint @ PremiumError::InvalidMint,
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(session_hash: [u8; 32], _token_amount: u64, _points_equivalent: u64)]
pub struct ChargePremium<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump,
    )]
    pub config: Account<'info, PremiumConfig>,

    #[account(
        init_if_needed,
        payer = user,
        seeds = [b"ledger", config.key().as_ref(), user.key().as_ref(), &session_hash],
        bump,
        space = 8 + SessionLedger::LEN
    )]
    pub ledger: Account<'info, SessionLedger>,

    #[account(
        mut,
        address = config.vault,
        constraint = vault.owner == config.key() @ PremiumError::VaultAuthorityMismatch,
        constraint = vault.mint == config.mint @ PremiumError::InvalidMint,
    )]
    pub vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = user_token_account.owner == user.key() @ PremiumError::InvalidUserTokenAccount,
        constraint = user_token_account.mint == config.mint @ PremiumError::InvalidMint,
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawFromVault<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump,
        has_one = authority,
    )]
    pub config: Account<'info, PremiumConfig>,

    #[account(
        mut,
        address = config.vault,
        constraint = vault.owner == config.key() @ PremiumError::VaultAuthorityMismatch,
        constraint = vault.mint == config.mint @ PremiumError::InvalidMint,
    )]
    pub vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = destination_token_account.mint == config.mint @ PremiumError::InvalidMint,
    )]
    pub destination_token_account: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

#[account]
pub struct PremiumConfig {
    pub authority: Pubkey,
    pub mint: Pubkey,
    pub vault: Pubkey,
    pub free_grant_amount: u64,
    pub points_per_token: u64,
    pub paused: bool,
    pub bump: u8,
    pub _reserved: [u8; 6],
}

impl PremiumConfig {
    pub const LEN: usize = 32 + 32 + 32 + 8 + 8 + 1 + 1 + 6;
}

#[account]
pub struct SessionLedger {
    pub config: Pubkey,
    pub user: Pubkey,
    pub session_hash: [u8; 32],
    pub total_granted: u64,
    pub total_spent: u64,
    pub points_charged: u64,
    pub created_at: i64,
    pub last_updated_at: i64,
    pub free_grant_claimed: bool,
    pub bump: u8,
    pub _reserved: [u8; 6],
}

impl SessionLedger {
    pub const LEN: usize = 32 + 32 + 32 + 8 + 8 + 8 + 8 + 8 + 1 + 1 + 6;
}

#[event]
pub struct ConfigInitialized {
    pub authority: Pubkey,
    pub mint: Pubkey,
    pub vault: Pubkey,
    pub free_grant_amount: u64,
    pub points_per_token: u64,
    pub at: i64,
}

#[event]
pub struct ConfigUpdated {
    pub authority: Pubkey,
    pub free_grant_amount: u64,
    pub points_per_token: u64,
    pub paused: bool,
    pub at: i64,
}

#[event]
pub struct FreeSessionGranted {
    pub user: Pubkey,
    pub session_hash: [u8; 32],
    pub amount: u64,
    pub points_equivalent: u64,
    pub at: i64,
}

#[event]
pub struct PremiumCharged {
    pub user: Pubkey,
    pub session_hash: [u8; 32],
    pub token_amount: u64,
    pub points_equivalent: u64,
    pub at: i64,
}

#[event]
pub struct VaultWithdrawn {
    pub authority: Pubkey,
    pub destination: Pubkey,
    pub amount: u64,
    pub at: i64,
}

#[error_code]
pub enum PremiumError {
    #[msg("Caller is not authorized for this action.")]
    Unauthorized,
    #[msg("Billing is paused.")]
    BillingPaused,
    #[msg("Provided amount is invalid.")]
    InvalidAmount,
    #[msg("points_per_token must be greater than zero.")]
    InvalidPointsRate,
    #[msg("Math overflow.")]
    MathOverflow,
    #[msg("Session ledger does not match provided seeds.")]
    LedgerMismatch,
    #[msg("Free grant already claimed for this wallet+session.")]
    FreeGrantAlreadyClaimed,
    #[msg("Vault token authority does not match config PDA.")]
    VaultAuthorityMismatch,
    #[msg("Invalid token mint for this operation.")]
    InvalidMint,
    #[msg("Invalid user token account for this operation.")]
    InvalidUserTokenAccount,
}
